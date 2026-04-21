import { inspect } from 'util';
let previous = Promise.resolve();
const color = (str, c) => {
    return `\x1b[${c}m${str}\x1b[0m`;
};
export const test = (title, fn) => {
    previous = previous.then(async () => {
        try {
            await fn();
            console.log(color(` ✔  ${title}`, 32));
        }
        catch (err) {
            const error = err;
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
//# sourceMappingURL=test.js.map