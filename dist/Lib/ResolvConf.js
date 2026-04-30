import fs from 'fs';
export class ResolvConf {
    static DEFAULT_PATH = '/etc/resolv.conf';
    static parse(content) {
        const out = {
            nameservers: [],
            search: [],
            sortlist: [],
            options: {}
        };
        for (const rawLine of content.split(/\r?\n/u)) {
            const stripped = ResolvConf._stripComment(rawLine).trim();
            if (stripped.length === 0) {
                continue;
            }
            const tokens = stripped.split(/\s+/u);
            const directive = tokens[0].toLowerCase();
            const args = tokens.slice(1);
            switch (directive) {
                case 'nameserver':
                    if (args.length > 0) {
                        out.nameservers.push(args[0]);
                    }
                    break;
                case 'search':
                    out.search = args.slice();
                    break;
                case 'domain':
                    if (args.length > 0) {
                        out.domain = args[0];
                    }
                    break;
                case 'sortlist':
                    out.sortlist = args.slice();
                    break;
                case 'options':
                    ResolvConf._mergeOptions(out.options, args);
                    break;
                default:
                    break;
            }
        }
        return out;
    }
    static fromFile(path = ResolvConf.DEFAULT_PATH) {
        const content = fs.readFileSync(path, 'utf8');
        return ResolvConf.parse(content);
    }
    static _stripComment(line) {
        const hash = line.indexOf('#');
        const semi = line.indexOf(';');
        const candidates = [hash, semi].filter((i) => i >= 0);
        if (candidates.length === 0) {
            return line;
        }
        return line.slice(0, Math.min(...candidates));
    }
    static _mergeOptions(target, tokens) {
        for (const tok of tokens) {
            const colon = tok.indexOf(':');
            const key = colon === -1 ? tok : tok.slice(0, colon);
            const value = colon === -1 ? '' : tok.slice(colon + 1);
            switch (key) {
                case 'ndots':
                    target.ndots = ResolvConf._parseInt(value, 1);
                    break;
                case 'timeout':
                    target.timeout = ResolvConf._parseInt(value, 5);
                    break;
                case 'attempts':
                    target.attempts = ResolvConf._parseInt(value, 2);
                    break;
                case 'rotate':
                    target.rotate = true;
                    break;
                case 'single-request':
                case 'single_request':
                    target.singleRequest = true;
                    break;
                case 'single-request-reopen':
                case 'single_request_reopen':
                    target.singleRequestReopen = true;
                    break;
                case 'inet6':
                    target.inet6 = true;
                    break;
                case 'edns0':
                    target.edns0 = true;
                    break;
                case 'trust-ad':
                    target.trustAd = true;
                    break;
                case 'no-aaaa':
                    target.noAaaa = true;
                    break;
                case 'no-tld-query':
                    target.noTldQuery = true;
                    break;
                default:
                    if (target.unknown === undefined) {
                        target.unknown = {};
                    }
                    target.unknown[key] = colon === -1 ? true : value;
                    break;
            }
        }
    }
    static _parseInt(s, fallback) {
        const n = Number.parseInt(s, 10);
        return Number.isFinite(n) ? n : fallback;
    }
}
//# sourceMappingURL=ResolvConf.js.map