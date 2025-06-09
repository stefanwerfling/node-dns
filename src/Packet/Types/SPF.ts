import {PacketTypes} from '../PacketTypes.js';
import {TXT} from './TXT.js';

/**
 * SPF
 */
export class SPF extends TXT {

    /**
     * Constructor
     * @param {string} data
     */
    public constructor(data: string = '') {
        super(data, PacketTypes.SPF);
    }

}