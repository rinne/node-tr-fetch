'use strict';

const HEADER = '  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n' +
      '                                 Dload  Upload   Total   Spent    Left  Speed\n';

const UNITS = [ [ 'k', 1024 ], [ 'M', 1024 ** 2 ], [ 'G', 1024 ** 3 ], [ 'T', 1024 ** 4 ], [ 'P', 1024 ** 5 ] ];

// A byte count in five columns, like curl's meter.
function size5(value) {
    value = Math.max(0, Math.floor(value));
    if (value < 100000) {
        return String(value).padStart(5);
    }
    for (const [unit, scale] of UNITS) {
        if (value < 100 * scale) {
            const tenths = Math.floor(value / (scale / 10));
            return `${Math.floor(tenths / 10)}.${tenths % 10}${unit}`.padStart(5);
        }
        if (value < 10000 * scale) {
            return `${Math.floor(value / scale)}${unit}`.padStart(5);
        }
    }
    return `${Math.floor(value / (1024 ** 5))}P`.padStart(5);
}

function time8(seconds) {
    if (! Number.isFinite(seconds)) {
        return '--:--:--';
    }
    seconds = Math.floor(seconds);
    const hours = Math.floor(seconds / 3600);
    if (hours >= 100) {
        return `${Math.floor(hours / 24)}d ${String(hours % 24).padStart(2, '0')}h`.padStart(8);
    }
    return `${String(hours).padStart(2)}:${String(Math.floor(seconds / 60) % 60).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}

function percent(part, total) {
    return String(total ? Math.floor((part * 100) / total) : 0).padStart(3);
}

class Progress {
    #mode;
    #stream;
    #started = Date.now();
    #timer;
    #total;
    #received = 0;
    #uploaded = 0;
    #samples = [];
    #bounce = 0;
    #finished = false;

    constructor(mode, stream = process.stderr) {
        this.#mode = mode;
        this.#stream = stream;
        if (mode === 'meter') {
            this.#write(HEADER);
        }
        this.#timer = setInterval(() => this.#render(), (mode === 'meter') ? 1000 : 200);
        this.#timer.unref();
    }

    expect(total) {
        this.#total = total;
    }

    upload(bytes) {
        this.#uploaded = bytes;
    }

    update(received) {
        this.#received = received;
    }

    finish() {
        if (this.#finished) {
            return;
        }
        this.#finished = true;
        clearInterval(this.#timer);
        this.#render(true);
        this.#write('\n');
    }

    #write(text) {
        try {
            this.#stream.write(text);
        } catch (_) {
            // The meter must not change the transfer outcome.
        }
    }

    #render(final = false) {
        const now = Date.now();
        if (this.#mode === 'bar') {
            this.#renderBar(final);
            return;
        }
        const spent = (now - this.#started) / 1000;
        this.#samples.push([ now, this.#received ]);
        while ((this.#samples.length > 1) && ((now - this.#samples[0][0]) > 5000)) {
            this.#samples.shift();
        }
        const [sampleTime, sampleBytes] = this.#samples[0];
        const current = (now > sampleTime) ? ((this.#received - sampleBytes) * 1000) / (now - sampleTime) :
              (spent ? this.#received / spent : 0);
        const dlSpeed = spent ? this.#received / spent : 0;
        const ulSpeed = spent ? this.#uploaded / spent : 0;
        const total = (this.#total ?? this.#received) + this.#uploaded;
        const done = this.#received + this.#uploaded;
        const expected = (this.#total !== undefined) && (dlSpeed > 0) ? this.#total / dlSpeed : undefined;
        const left = (expected === undefined) ? undefined : Math.max(0, expected - spent);
        this.#write(`\r${percent(done, total)} ${size5(total)}  ${percent(this.#received, this.#total)} ${size5(this.#received)}  ` +
                    `${percent(this.#uploaded, this.#uploaded)} ${size5(this.#uploaded)}  ${size5(dlSpeed)}  ${size5(ulSpeed)} ` +
                    `${time8(expected)} ${time8(spent)} ${time8(left)} ${size5(final ? dlSpeed : current)}`);
    }

    #renderBar(final) {
        const width = Math.max(20, (this.#stream.columns || Number(process.env.COLUMNS) || 80) - 1);
        const length = width - 7;
        if (this.#total) {
            const fraction = Math.min(1, this.#received / this.#total);
            const bar = '#'.repeat(Math.round(fraction * length)).padEnd(length);
            this.#write(`\r${bar} ${(fraction * 100).toFixed(1).padStart(5)}%`);
        } else if (final) {
            this.#write(`\r${'#'.repeat(length).padEnd(width)}`);
        } else {
            const position = this.#bounce++ % ((length - 5) * 2);
            const offset = (position < (length - 5)) ? position : ((length - 5) * 2) - position;
            this.#write(`\r${(' '.repeat(offset) + '-=O=-').padEnd(width)}`);
        }
    }
}

module.exports = Progress;
