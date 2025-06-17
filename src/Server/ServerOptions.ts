import https from 'https';

/**
 * Server options
 */
export type ServerOptions = {
    udp?: {
        type?: 'udp4' | 'udp6';
    };
    doh?: {
        ssl?: boolean;
        options: https.ServerOptions;
    };
};