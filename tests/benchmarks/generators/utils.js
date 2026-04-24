/**
 * Seeded Random Utility for Deterministic Benchmarking (Seed: 1337)
 */
class SeededRandom {
    constructor(seed = 1337) {
        this.seed = seed;
    }
    next() {
        this.seed = (this.seed * 9301 + 49297) % 233280;
        return this.seed / 233280;
    }
    range(min, max) {
        return Math.floor(this.next() * (max - min + 1)) + min;
    }
    pick(arr) {
        return arr[this.range(0, arr.length - 1)];
    }
}

module.exports = SeededRandom;
