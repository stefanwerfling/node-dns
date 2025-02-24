import {PacketClass} from './PacketClass.js';
import {PacketTypes} from './PacketTypes.js';

/**
 * Resource record format
 * @docs https://tools.ietf.org/html/rfc1035#section-4.1.3
 */
export class PacketResource {

    public name: string;

    public type: PacketTypes|number;

    public class: PacketClass|number;

    public ttl: number;

    public constructor(
        name: string = '',
        type: PacketTypes|number = PacketTypes.ANY,
        cls: PacketClass|number = PacketClass.ANY,
        ttl: number = 300
    ) {
        this.name = name;
        this.type = type;
        this.class = cls;
        this.ttl = ttl;
    }


}