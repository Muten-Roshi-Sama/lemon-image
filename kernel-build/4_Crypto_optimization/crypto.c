#define pr_fmt(fmt) "crypto_challenge: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/thermal.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/proc_fs.h>

#define MAX_CORES 4
#define WORK_SIZE 4096
#define KEY_SIZE 16           // AES-128
#define IV_SIZE 16

#define SAMPLE_PERIOD_MS 100
#define BENCH_DURATION_SEC 60
#define THERMAL_LIMIT_MILLIC 65000
#define MAX_SAMPLES (BENCH_DURATION_SEC * 1000 / SAMPLE_PERIOD_MS)

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;


// ------- Callup Logic --------
/*
    1. mod_init : 
        1.1 start_worker   : 
            - starts all the workers
            - allocate buffers, create keys, crypto requests...
            - binds worker_fn on a thread


    2. control_fn  : 
        - runs  on a thread
        - starts sampling 


    2. worker_fn :
        - do_crypto : encrypts one buffer (= one operation towards the score)
        - atomic64_inc : 


*/








// ------- structures -------
struct worker {
    /* Each worker needs its own crypto state and own execution context.  
    */
    struct task_struct *task;       // The kernel thread handle. Used to stop, wake, or bind the thread.
    struct crypto_skcipher *tfm;   // The crypto “transform” object. Represents the AES-CBC cipher configuration.
    struct skcipher_request *req; // A request object for a single encryption operation. Reused to avoid reallocating each time.

    u8 *buf;             // The data buffer that gets encrypted.
    u8 key[KEY_SIZE];   // AES key, 16 bytes for 128-bit AES.
    u8 iv[IV_SIZE];    // Initialization vector for CBC mode.

    int cpu_id;    // Which CPU this worker should run on. Used with kthread_bind().
};

struct sample {
    u64 ops;
    int temp[MAX_CORES];
};

struct challenge_ctx {
    /* GLOBAL STATE (shared accross all threads)
    */
    struct worker workers[MAX_CORES];           // The 4 worker records.
    struct thermal_zone_device *tz[MAX_CORES]; // Thermal zones for the 4 CPU cores.

    struct sample samples[MAX_SAMPLES];      // Logged temperature / ops samples over time.
    int sample_count;                       // How many samples are valid.

    atomic64_t ops;         // Total number of crypto ops completed. Atomic because multiple threads increment it concurrently.

    int worker_count;     // Number of active workers.
    bool run;            // “Green light” for workers to compute.
    bool stop;          // Global stop flag.

    int duty_on_ms;     // How long workers are allowed to run
    int duty_off_ms;   // How long they must sleep.

    unsigned long start_jiffies;      // Benchmark start time.
    struct timer_list sample_timer;  // Timer used to call the sampling function periodically.

    u64 final_score;  // Cached final score.
    int invalid;     // Set if any thermal limit is exceeded.
};

static struct challenge_ctx ctx;

/* ---------------- CRYPTO ---------------- */

static int do_crypto(struct worker *w)
{
    // 1. Prepare the buffer.
    struct scatterlist sg;
    sg_init_one(&sg, w->buf, WORK_SIZE);

    // 2. Configure the encryption request.
    skcipher_request_set_crypt(w->req, &sg, &sg, WORK_SIZE, w->iv);

    // 3. Encrypt the buffer
    return crypto_skcipher_encrypt(w->req);
}

/* ---------------- WORKER ---------------- */

static int worker_fn(void *arg)
{
    struct worker *w = arg;

    // pr_info("worker %d started\n", w->cpu_id);

    while (!kthread_should_stop()) {

        if (!ctx.run) {
            set_current_state(TASK_INTERRUPTIBLE);
            /* Simple schedule() call makes the thread starve,
             * misses the wakeup signal somehow. */
            schedule_timeout_interruptible(msecs_to_jiffies(10));
            continue;
        }

        do_crypto(w);
        atomic64_inc(&ctx.ops);

        /* Make sure we reschedule to avoid lockups under heavy loads */
        cond_resched();
    }

    return 0;
}

static int start_worker(int cpu)
{
    // 1. Allocate buffer.
    struct worker *w = &ctx.workers[cpu];

    // 2. Set key and IV.
    memset(w, 0, sizeof(*w));
    w->cpu_id = cpu;

    w->buf = kmalloc(WORK_SIZE, GFP_KERNEL);
    if (!w->buf)
        return -ENOMEM;

    memset(w->buf, 0xAA, WORK_SIZE);

    memset(w->key, 0x11, KEY_SIZE);
    memset(w->iv, 0x22, IV_SIZE);

    // 3. Select AES-CBC cipher.
    w->tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
    if (IS_ERR(w->tfm))
        return PTR_ERR(w->tfm);

    crypto_skcipher_setkey(w->tfm, w->key, KEY_SIZE);

    // 4. Create crypto request.
    w->req = skcipher_request_alloc(w->tfm, GFP_KERNEL);
    if (!w->req)
        return -ENOMEM;

    // 5. Create kernel thread.
    w->task = kthread_create(worker_fn, w, "crypto_%d", cpu);   //! calls worker_fn()
    if (IS_ERR(w->task))
        return PTR_ERR(w->task);
    
    // 6. Bind it to a CPU core.
    kthread_bind(w->task, cpu); /* Bind *before* starting thread */

    // 7. Wake it up.
    wake_up_process(w->task);

    return 0;
}

static void stop_worker(int cpu)
{
    struct worker *w = &ctx.workers[cpu];
    struct task_struct *task;

    // pr_info("stopping worker %d task=%p\n", cpu, w->task);

    if (!w)
        return;

    /* atomically grab and NULL the pointer */
    task = xchg(&w->task, NULL);

    if (!task)
        return;

    /* 1. Stop thread first (ensures no more crypto use) */
    kthread_stop(task);
    // w->task = NULL;

    /* 2. Free crypto request */
    if (w->req) {
        skcipher_request_free(w->req);
        w->req = NULL;
    }

    /* 3. Free cipher transform */
    if (w->tfm) {
        crypto_free_skcipher(w->tfm);
        w->tfm = NULL;
    }

    /* 4. Free buffer */
    kfree(w->buf);
    w->buf = NULL;
}

/* ---------------- THERMAL ---------------- */

static int read_temp(int cpu)
{
    int temp;

    if (!ctx.tz[cpu])
        return 0;

    if (thermal_zone_get_temp(ctx.tz[cpu], &temp))
        return 0;

    return temp;
}

/* ---------------- SAMPLING ---------------- */

static void sample_fn(struct timer_list *t)
{
    // 1. Read operation count
    struct sample *s;
    int i;

    // 2. Return if Max samples per cycle is reached
    if (ctx.sample_count >= MAX_SAMPLES)
        return;

    // 3. Add one to sample count
    s = &ctx.samples[ctx.sample_count++];
    s->ops = atomic64_read(&ctx.ops);

    // 4. Read each core T°
    for (i = 0; i < MAX_CORES; i++) {
        int temp = read_temp(i);
        s->temp[i] = temp;
        if (temp > THERMAL_LIMIT_MILLIC) // SET flag if t° exceeds
            ctx.invalid = 1;
    }
    // 5. Reschedule itself 
    mod_timer(&ctx.sample_timer, jiffies + msecs_to_jiffies(SAMPLE_PERIOD_MS));
}

static void start_sampling(void)
{
    ctx.sample_count = 0;

    timer_setup(&ctx.sample_timer, sample_fn, 0);
    mod_timer(&ctx.sample_timer, jiffies + msecs_to_jiffies(SAMPLE_PERIOD_MS));
}

static void stop_sampling(void)
{
    del_timer_sync(&ctx.sample_timer);
}

/* ---------------- SCORING ---------------- */

static void compute_score(void)
{
    int i, c;

    /* Compute the count of operations done */
    u64 ops0 = ctx.samples[0].ops;
    u64 ops1 = ctx.samples[ctx.sample_count - 1].ops;

    u64 ops = ops1 - ops0;

    if (ctx.invalid) {
        ctx.final_score = 0;
        return;
    }

    u64 thermal_cost = 0;

    int init_temp[MAX_CORES];
    for (c = 0; c < MAX_CORES; c++) {
        init_temp[c] = ctx.samples[0].temp[c];
    }

    for (i = 1; i < ctx.sample_count; i++) {
        for (c = 0; c < MAX_CORES; c++) {

            int t = ctx.samples[i].temp[c];
            int delta = t - init_temp[c];

            if (delta < 0)
                delta = 0;

            /* quadratic penalty: hot cores dominate */
            thermal_cost += (u64)delta * (u64)delta;
        }
    }

    /* On ARM 32bits, we don't have native 64-bit operations,
     * need helpers. And we need 64-bit variable for large
     * counters.
     */
    u64 throughput = div64_u64(ops,BENCH_DURATION_SEC);

    u64 denom = div64_u64(thermal_cost,100000) + 1;
    u64 num = throughput * 100000ULL;
    // pr_info("thermal cost: %lld\n", thermal_cost);
    // pr_info("throughput: %lld\n", throughput);
    ctx.final_score = div64_u64(num, denom);
}

/* ---------------- CONTROL THREAD ---------------- */

static int control_fn(void *arg)
{
    // 1. Start Sampling
    // int i;
    ctx.start_jiffies = jiffies;
    start_sampling();
    ctx.stop = false;

    // 2. Runs until benchmark timer is over.
    while (!kthread_should_stop()) {

        // Interrupt 1 :cpu overheats
        if (ctx.stop) {
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout_interruptible(msecs_to_jiffies(10));
            continue;
        }

        // Interrupt 2 : time window ends
        if (time_after(jiffies, ctx.start_jiffies + BENCH_DURATION_SEC * HZ)) {

            ctx.run = false;
            ctx.stop = true;
            stop_sampling();

            pr_info("Benchmark stopped.\n");

            compute_score();
            pr_info("Final score: %lld, operations: %lld\n", ctx.final_score, atomic64_read(&ctx.ops));

            continue; // skip the rest of the loop
        }


        /* ------------------
         * --- REGULATION ---
         * vvvvvvvvvvvvvvvvvv */

        // duty cycle
        ctx.run = true;
        msleep(ctx.duty_on_ms);

        ctx.run = false;
        msleep(ctx.duty_off_ms);

        /* ^^^^^^^^^^^^^^^^^^
         * --- REGULATION ---
         * ------------------ */
    }

    return 0;
}

static struct task_struct *ctrl_task;

/* ---------------- DEBUGFS ---------------- */

static ssize_t stats_read(struct file *f, char __user *buf, size_t len, loff_t *ppos)
{
    char out[256];
    int l;

    l = snprintf(out, sizeof(out),
        "ops=%lld samples=%d score=%lld invalid=%d\n",
        atomic64_read(&ctx.ops),
        ctx.sample_count,
        ctx.final_score,
        ctx.invalid);

    return simple_read_from_buffer(buf, len, ppos, out, l);
}

static const struct proc_ops stats_fops = {
    .proc_read = stats_read,
};

/* ---------------- INIT / EXIT ---------------- */

static int __init mod_init(void)
{
    // 1. Set on and off delays for the default (and crude) regulation
    int i;
    memset(&ctx, 0, sizeof(ctx));
    ctx.duty_on_ms = 20;
    ctx.duty_off_ms = 20;

    // 2. Set the thermal zones to monitor
    for (i = 0; i < MAX_CORES; i++) {
        char name[32];
        snprintf(name, sizeof(name), "cpu%d-thermal", i);
        ctx.tz[i] = thermal_zone_get_zone_by_name(name);
    }

    // 3. Create the procfs entry
    proc_dir = proc_mkdir("crypto_challenge", NULL);
    if (!proc_dir)
        return -ENOMEM;

    proc_file = proc_create("stats", 0444, proc_dir, &stats_fops);
    if (!proc_file)
        return -ENOMEM;

    // 4. Call the start_worker procedure to launch the worker threads
    for (i = 0; i < MAX_CORES; i++)
        start_worker(i);                //! start_worker

    // 5. Create and run the control thread
    ctrl_task = kthread_run(control_fn, NULL, "ctrl");  //! control_fn

    pr_info("crypto_thermal_challenge loaded\n");
    pr_info("Benchmark started\n");
    return 0;
}

static void __exit mod_exit(void)
{
    // 1. Stop the control thread
    int i;
    if (ctrl_task) {
        // pr_info("Stopping control thread...\n");
        kthread_stop(ctrl_task);
        ctrl_task = NULL;
        // pr_info("Stopping control thread: done\n");
    }
    stop_sampling();


    // 2. Stop the worker threads
    for (i = 0; i < MAX_CORES; i++) {
        // pr_info("Stopping thread #%d...\n", i);
        stop_worker(i);
        // pr_info("Stopping thread #%d: done\n", i);
    }

    // 3. Remove the procfs entry It is important to stop the threads in one single place, here when removing the module from the kernel.
    if (proc_file)
        remove_proc_entry("stats", proc_dir);

    if (proc_dir)
        remove_proc_entry("crypto_challenge", NULL);

    pr_info("crypto_thermal_challenge unloaded\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ECAM");
MODULE_DESCRIPTION("Thermal-aware crypto challenge");