const DEFAULT_SCHEDULE = [1000, 2000, 4000, 8000];
export class MdnsAnnouncer {
    _server;
    _records;
    _schedule;
    _steadyStateMs;
    _goodbyeOnStop;
    _initialAnnounce;
    _timer;
    _stepIndex;
    _running;
    _onError;
    constructor(server, records, options = {}) {
        this._server = server;
        this._records = records;
        this._schedule = options.schedule ?? DEFAULT_SCHEDULE.slice();
        this._steadyStateMs = Math.max(0, options.steadyStateMs ?? 0);
        this._goodbyeOnStop = options.goodbyeOnStop ?? true;
        this._initialAnnounce = options.initialAnnounce ?? false;
        this._timer = null;
        this._stepIndex = 0;
        this._running = false;
        this._onError = null;
    }
    start() {
        if (this._running) {
            return this;
        }
        this._running = true;
        this._stepIndex = 0;
        if (this._initialAnnounce) {
            this._announce();
        }
        this._scheduleNext();
        return this;
    }
    async stop() {
        if (!this._running) {
            return;
        }
        this._running = false;
        if (this._timer !== null) {
            clearTimeout(this._timer);
            this._timer = null;
        }
        if (this._goodbyeOnStop && this._records.length > 0) {
            try {
                await this._server.goodbye(this._records);
            }
            catch (err) {
                this._reportError(err);
            }
        }
    }
    on(event, listener) {
        if (event === 'error') {
            this._onError = listener;
        }
        return this;
    }
    get running() {
        return this._running;
    }
    _scheduleNext() {
        if (!this._running) {
            return;
        }
        let delay;
        if (this._stepIndex < this._schedule.length) {
            delay = this._schedule[this._stepIndex];
        }
        else if (this._steadyStateMs > 0) {
            delay = this._steadyStateMs;
        }
        else {
            this._running = false;
            return;
        }
        this._timer = setTimeout(() => {
            this._timer = null;
            this._stepIndex++;
            this._announce();
            this._scheduleNext();
        }, delay);
        this._timer.unref?.();
    }
    _announce() {
        if (this._records.length === 0) {
            return;
        }
        this._server.announce(this._records).catch((err) => this._reportError(err));
    }
    _reportError(err) {
        if (this._onError !== null) {
            this._onError(err instanceof Error ? err : new Error(String(err)));
        }
    }
}
//# sourceMappingURL=MdnsAnnouncer.js.map