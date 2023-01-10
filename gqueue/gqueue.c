#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");

// Procfs entry
static struct proc_dir_entry *gqueue_proc_entry;

// Linked list
struct gqueue_node {
    char* data;
    size_t len;
    struct gqueue_node *next;
};
static struct gqueue_node *gqueue_head, *gqueue_tail;
static struct mutex gqueue_lock;

// Dummy node
static const struct gqueue_node gqueue_dummy_node = {
    .data = "End of queue.\n",
    .len = 14,
    .next = NULL
};


// Procfs read/write
static ssize_t gqueue_proc_read(struct file *file, char __user *ubuf, size_t count, loff_t *offset) {
    const struct gqueue_node *node;
    ssize_t nb;

    // Fetch node
    mutex_lock(&gqueue_lock);
    node = gqueue_head;
    if (node == NULL) {
        node = &gqueue_dummy_node;
    }

    // Copy data
    if (*offset >= node->len) {
        *offset = 0;

        // Delete node
        if (node == gqueue_head) {
            if (node == gqueue_tail) {
                gqueue_head = gqueue_tail = NULL;
            } else {
                gqueue_head = node->next;
            }
            kfree(node->data);
            kfree(node);
        }
        mutex_unlock(&gqueue_lock);

        return 0;
    }
    mutex_unlock(&gqueue_lock);

    nb = copy_to_user(ubuf, node->data, node->len);
    if (nb != 0) {
        return -EFAULT;
    }
    *offset += node->len;
    return node->len;
}

static ssize_t gqueue_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *offset) {
    char *kbuf;
    ssize_t nb;
    struct gqueue_node *node;

    // Move to kernel buffer
    kbuf = kmalloc(count, GFP_KERNEL);
    if (kbuf == NULL) {
        return -ENOMEM;
    }
    nb = copy_from_user(kbuf, ubuf, count);
    if (nb != 0) {
        return -EFAULT;
    }

    // New node
    node = kmalloc(sizeof(struct gqueue_node), GFP_KERNEL);
    if (node == NULL) {
        return -ENOMEM;
    }
    node->data = kbuf;
    node->len = count;
    node->next = NULL;

    // Insert node
    mutex_lock(&gqueue_lock);
    if (gqueue_tail == NULL) {
        gqueue_head = gqueue_tail = node;
    } else {
        gqueue_tail->next = node;
        gqueue_tail = node;
    }
    mutex_unlock(&gqueue_lock);

    return count;
}

// GQueue module
static const struct proc_ops gqueue_proc_ops = {
    .proc_read = gqueue_proc_read,
    .proc_write = gqueue_proc_write
};

static int __init gqueue_init(void) {
    pr_info("Loading GQueue");

    gqueue_proc_entry = proc_create("gqueue", 0666, NULL, &gqueue_proc_ops);

    gqueue_head = gqueue_tail = NULL;
    mutex_init(&gqueue_lock);

    return 0;
}

static void __exit gqueue_cleanup(void) {
    pr_info("Unloading GQueue");

    proc_remove(gqueue_proc_entry);

    mutex_destroy(&gqueue_lock);
}

module_init(gqueue_init);
module_exit(gqueue_cleanup);
