export type ResolvConfOptions = {
    ndots?: number;
    timeout?: number;
    attempts?: number;
    rotate?: boolean;
    singleRequest?: boolean;
    singleRequestReopen?: boolean;
    inet6?: boolean;
    edns0?: boolean;
    trustAd?: boolean;
    noAaaa?: boolean;
    noTldQuery?: boolean;
    unknown?: Record<string, string | boolean>;
};
export type ParsedResolvConf = {
    nameservers: string[];
    search: string[];
    domain?: string;
    sortlist: string[];
    options: ResolvConfOptions;
};
export declare class ResolvConf {
    static readonly DEFAULT_PATH: string;
    static parse(content: string): ParsedResolvConf;
    static fromFile(path?: string): ParsedResolvConf;
    protected static _stripComment(line: string): string;
    protected static _mergeOptions(target: ResolvConfOptions, tokens: string[]): void;
    protected static _parseInt(s: string, fallback: number): number;
}
