/**
 * Sentinel: Worker Pool Manager (v1.0)
 */

const { Worker } = require('worker_threads');
const path = require('path');
const os = require('os');

class WorkerPool {
    constructor() {
        this.maxWorkers = os.cpus().length;
        this.queue = [];
        this.activeWorkers = 0;
    }

    async runTask(taskData) {
        return new Promise((resolve, reject) => {
            // Adaptive Timeout: 800ms base + 0.1ms per character, max 5s
            const adaptiveLimit = Math.min(5000, 800 + (taskData.patch?.length || 0) * 0.1);
            
            const timeout = setTimeout(() => {
                if (task) {
                    task.aborted = true;
                    reject(new Error(`SCAN_TIMEOUT: File ${taskData.filename} exceeded ${Math.round(adaptiveLimit)}ms limit.`));
                }
            }, adaptiveLimit);

            const task = { 
                taskData, 
                resolve: (res) => { clearTimeout(timeout); resolve(res); }, 
                reject: (err) => { clearTimeout(timeout); reject(err); },
                aborted: false 
            };

            this.queue.push(task);
            this.processNext();
        });
    }

    processNext() {
        if (this.activeWorkers >= this.maxWorkers || this.queue.length === 0) {
            return;
        }

        const task = this.queue.shift();
        if (task.aborted) {
            this.processNext();
            return;
        }

        const { taskData, resolve, reject } = task;
        this.activeWorkers++;

        const worker = new Worker(path.join(__dirname, '../workers/scanner_worker.js'), {
            workerData: taskData,
            stdout: true
        });

        worker.stdout.on('data', (data) => {
            process.stdout.write(`[WORKER-${worker.threadId}] ${data}`);
        });

        worker.on('message', (result) => {
            if (result.status === 'success') {
                resolve(result);
            } else {
                reject(new Error(result.error));
            }
            worker.terminate(); // Clean up immediately
        });

        worker.on('error', (err) => {
            reject(err);
            worker.terminate();
        });
        
        worker.on('exit', (code) => {
            this.activeWorkers--;
            this.processNext();
        });
    }
}

module.exports = new WorkerPool();
