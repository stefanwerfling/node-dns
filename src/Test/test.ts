import {inspect} from 'util';

let previous = Promise.resolve();

const color = (str: string, c: number): string => {
    return `\x1b[${c}m${str}\x1b[0m`;
};

/**
 * super tiny testing framework
 *
 * @author Liu song <hi@lsong.org>
 * @github https://github.com/song940
 */
export const test = (title: string, fn: () => void | Promise<void>): Promise<void> => {
    previous = previous.then(async() => {
        try {
            await fn();
            console.log(color(` ✔  ${title}`, 32));
        } catch (err: unknown) {
            const error = err as Error & {expected?: unknown; actual?: unknown};

            console.error(color(` ✘  ${title}`, 31));
            console.log();
            console.log(color(`   ${error.name}: ${error.message}`, 31));
            console.error(color(`   expected: ${inspect(error.expected)}`, 32));
            console.error(color(`     actual: ${inspect(error.actual)}`, 31));
            console.log(error.stack);
            console.log();
            process.exit(1);
        }
    });

    return previous;
};