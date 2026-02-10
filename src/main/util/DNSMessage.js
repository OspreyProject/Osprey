/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"use strict";

class DNSMessage {

    /**
     * Constructor function for creating a DNSMessage object.
     */
    constructor() {
        this.id = 0;            // IDentification field (16 bits)
        this.flags = 0;         // Flags (16 bits)
        this.qdCount = 0;       // Number of entries in the question section
        this.anCount = 0;       // Number of resource records in the answer section
        this.nsCount = 0;       // Number of name server resource records in the authority records section
        this.arCount = 0;       // Number of resource records in the additional records section

        this.questions = [];    // Array of question objects, each with qname, qtype, and qclass
        this.answers = [];      // Array of answer resource records (RRs), each with name, type, class, ttl, rdlength, rdataRaw, and rdata
        this.authorities = [];  // Array of authority resource records (RRs), each with name, type, class, ttl, rdlength, rdataRaw, and rdata
        this.additionals = [];  // Array of additional resource records (RRs), each with name, type, class, ttl, rdlength, rdataRaw, and rdata
    }

    /**
     * Extracts the QR (Query/Response) flag from the DNS message flags.
     *
     * @returns {number} - The QR flag value, which is the 15th bit of the flags field in the DNS message header.
     */
    qr() {
        return this.flags >>> 15 & 0x1;
    }

    /**
     * Extracts the OPCODE from the DNS message flags.
     *
     * @returns {number} - The OPCODE value, which is the 4 bits from the 14th to the 11th bit of the flags field in the DNS message header.
     */
    opcode() {
        return this.flags >>> 11 & 0xF;
    }

    /**
     * Extracts the AA (Authoritative Answer) flag from the DNS message flags.
     *
     * @returns {number} - The AA flag value, which is the 10th bit of the flags field in the DNS message header.
     */
    aa() {
        return this.flags >>> 10 & 0x1;
    }

    /**
     * Extracts the TC (Truncated) flag from the DNS message flags.
     *
     * @returns {number} - The TC flag value, which is the 9th bit of the flags field in the DNS message header.
     */
    tc() {
        return this.flags >>> 9 & 0x1;
    }

    /**
     * Extracts the RD (Recursion Desired) flag from the DNS message flags.
     *
     * @returns {number} - The RD flag value, which is the 8th bit of the flags field in the DNS message header.
     */
    rd() {
        return this.flags >>> 8 & 0x1;
    }

    /**
     * Extracts the RA (Recursion Available) flag from the DNS message flags.
     *
     * @returns {number} - The RA flag value, which is the 7th bit of the flags field in the DNS message header.
     */
    ra() {
        return this.flags >>> 7 & 0x1;
    }

    /**
     * Extracts the Z (Reserved) flag from the DNS message flags.
     *
     * @returns {number} - The Z flag value, which is the 6th bit of the flags field in the DNS message header.
     */
    z() {
        return this.flags >>> 6 & 0x1;
    }

    /**
     * Extracts the AD (Authenticated Data) flag from the DNS message flags.
     *
     * @returns {number} - The AD flag value, which is the 5th bit of the flags field in the DNS message header.
     */
    ad() {
        return this.flags >>> 5 & 0x1;
    }

    /**
     * Extracts the CD (Checking Disabled) flag from the DNS message flags.
     *
     * @returns {number} - The CD flag value, which is the 4th bit of the flags field in the DNS message header.
     */
    cd() {
        return this.flags >>> 4 & 0x1;
    }

    /**
     * Extracts the RCODE (Response Code) from the DNS message flags.
     *
     * @returns {number} - The RCODE value, which is the lower 4 bits of the flags field in the DNS message header.
     */
    rcode() {
        return this.flags & 0xF;
    }

    /**
     * Checks whether the DNS message contains any additional records in the additionals section.
     *
     * @returns {boolean} - Returns true if there are additional records in the additionals section, false otherwise.
     */
    hasAdditional() {
        return this.additionals.length > 0;
    }

    /**
     * Checks whether the DNS message contains any answer records in the answers section.
     *
     * @returns {boolean} - Returns true if there are answer records in the answers section, false otherwise.
     */
    hasAnswers() {
        return this.answers.length > 0;
    }

    /**
     * Checks whether the DNS message contains any authority records in the authorities section.
     *
     * @returns {boolean} - Returns true if there are authority records in the authorities section, false otherwise.
     */
    hasAuthorities() {
        return this.authorities.length > 0;
    }

    /**
     * Checks whether any RR (in any section) has the specified type.
     *
     * @param {number} type - The DNS RR type to check for in any section of the DNS message.
     * @returns {boolean} - Returns true if any RR in any section has the specified type, false otherwise.
     */
    hasRRType(type) {
        return this.sectionHasType(this.answers, type) ||
            this.sectionHasType(this.authorities, type) ||
            this.sectionHasType(this.additionals, type);
    }

    /**
     * Checks whether any RR in the answers section has the specified type.
     *
     * @param {number} type - The DNS RR type to check for in the answers section.
     * @returns {boolean} - Returns true if any RR in the answers section has the specified type, false otherwise.
     */
    hasAdditionalRRType(type) {
        return this.sectionHasType(this.additionals, type);
    }

    /**
     * Checks whether any RR in the given section has the specified type.
     *
     * @param {Array} section - An array of Resource Records (RRs) to check for the specified type.
     * @param {number} type - The DNS RR type to check for in the given section.
     * @returns {boolean} - Returns true if any RR in the section has the specified type, false otherwise.
     */
    sectionHasType(section, type) {
        return section.some(rr => rr.type === type);
    }

    /**
     * Checks whether any RR (in any section) contains the provided domain name
     * either as the RR owner name OR inside the RDATA for name-bearing types
     * (CNAME/NS/PTR/MX/SOA and a few others).
     *
     * @param {string} domain - The domain name to search for in the RRs.
     * @return {boolean} - Returns true if the domain name is found in any RR, false otherwise.
     */
    containsNameInAnyRR(domain) {
        const needle = DNSMessage.normalizeName(domain);
        const all = [...this.answers, ...this.authorities, ...this.additionals];

        for (const rr of all) {
            if (DNSMessage.normalizeName(rr.name) === needle) {
                return true;
            }

            // name-bearing RDATA
            const r = rr.rdata;
            if (!r) {
                continue;
            }

            if (typeof r === "string" && DNSMessage.normalizeName(r) === needle) {
                return true;
            }

            // MX: { exchange, preference }
            if (r.exchange && DNSMessage.normalizeName(r.exchange) === needle) {
                return true;
            }

            // SOA: { mname, rname, ... }
            if (r.mname && DNSMessage.normalizeName(r.mname) === needle) {
                return true;
            }
            if (r.rname && DNSMessage.normalizeName(r.rname) === needle) {
                return true;
            }

            // SRV: { target, ... }
            if (r.target && DNSMessage.normalizeName(r.target) === needle) {
                return true;
            }
        }
        return false;
    }

    /**
     * Parses a DNS message from a byte array.
     *
     * @param {Uint8Array|ArrayBuffer} bytes - The byte array containing the DNS message.
     * @returns {DNSMessage} - The parsed DNSMessage object.
     */
    static parse(bytes) {
        const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

        const msg = new DNSMessage();
        let off = 0;

        const readU16 = () => {
            if (off + 2 > u8.length) {
                throw new Error("Truncated DNS message (u16).");
            }

            const v = view.getUint16(off);
            off += 2;
            return v;
        };

        const readU32 = () => {
            if (off + 4 > u8.length) {
                throw new Error("Truncated DNS message (u32).");
            }

            const v = view.getUint32(off);
            off += 4;
            return v;
        };

        const readBytes = n => {
            if (off + n > u8.length) {
                throw new Error("Truncated DNS message (bytes).");
            }

            const slice = u8.subarray(off, off + n);
            off += n;
            return slice;
        };

        // Header (12 bytes)
        msg.id = readU16();
        msg.flags = readU16();
        msg.qdCount = readU16();
        msg.anCount = readU16();
        msg.nsCount = readU16();
        msg.arCount = readU16();

        const maxRecords = 1000;

        // Basic sanity check to prevent parsing extremely large or
        // malformed messages that could cause performance issues
        if (msg.qdCount > maxRecords ||
            msg.anCount > maxRecords ||
            msg.nsCount > maxRecords ||
            msg.arCount > maxRecords) {
            throw new Error("DNS message contains unreasonable record count.");
        }

        // Questions
        for (let i = 0; i < msg.qdCount; i++) {
            const qname = DNSMessage.readName(u8, {off});
            off = qname.off;
            const qtype = readU16();
            const qclass = readU16();
            msg.questions.push({qname: qname.name, qtype, qclass});
        }

        // Resource Record reader
        const readRR = () => {
            const nm = DNSMessage.readName(u8, {off});
            off = nm.off;

            const type = readU16();
            const rrclass = readU16();
            const ttl = readU32();
            const rdlength = readU16();
            const rdataStart = off;
            const rdataBytes = readBytes(rdlength); // advances off

            const rr = {
                name: nm.name,
                type,
                class: rrclass,
                ttl,
                rdlength,
                rdataRaw: rdataBytes,
                rdata: null
            };

            // Parse some common RDATA forms
            rr.rdata = DNSMessage.parseRData(u8, type, rdataStart, rdlength);
            return rr;
        };

        // Answers
        for (let i = 0; i < msg.anCount; i++) {
            msg.answers.push(readRR());
        }

        // Authorities
        for (let i = 0; i < msg.nsCount; i++) {
            msg.authorities.push(readRR());
        }

        // Additionals
        for (let i = 0; i < msg.arCount; i++) {
            msg.additionals.push(readRR());
        }
        return msg;
    }

    /**
     * Parses RDATA based on the RR type.
     *
     * @param {Uint8Array} array - The byte array containing the DNS message.
     * @param {number} type - The RR type to determine how to parse the RDATA.
     * @param {number} rdataStart - The starting offset of the RDATA in the byte array.
     * @param {number} rdlength - The length of the RDATA in bytes.
     */
    static parseRData(array, type, rdataStart, rdlength) {
        // Checks if the RDATA start and length are within the bounds of the array
        if (rdataStart < 0 || rdataStart + rdlength > array.length) {
            console.warn(`RDATA bounds are out of array limits (start: ${rdataStart}, length: ${rdlength}, array length: ${array.length}).`);
            return "(Invalid RDATA bounds)";
        }

        const view = new DataView(array.buffer, array.byteOffset, array.byteLength);
        const end = rdataStart + rdlength;

        const readU16At = pos => {
            if (pos + 2 > end) {
                throw new Error("Truncated RDATA (u16).");
            }
            return view.getUint16(pos);
        };

        const readU32At = pos => {
            if (pos + 4 > end) {
                throw new Error("Truncated RDATA (u32).");
            }
            return view.getUint32(pos);
        };

        const lengthA = 4;
        const lengthAAAA = 16;
        const lengthSOAMin = 20;
        const lengthSRVMin = 6;

        // A (1): 4 bytes IPv4
        if (type === DNSMessage.RRType.A && rdlength === lengthA) {
            const b = array.subarray(rdataStart, end);
            return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
        }

        // AAAA (28): 16 bytes IPv6 (simple formatting)
        if (type === DNSMessage.RRType.AAAA && rdlength === lengthAAAA) {
            const parts = [];

            for (let i = 0; i < lengthAAAA; i += 2) {
                parts.push((array[rdataStart + i] << 8 | array[rdataStart + i + 1]).toString(16));
            }
            return parts.join(":");
        }

        // CNAME (5), NS (2), PTR (12): a domain name
        if (type === DNSMessage.RRType.CNAME ||
            type === DNSMessage.RRType.NS ||
            type === DNSMessage.RRType.PTR) {
            const nm = DNSMessage.readName(array, {off: rdataStart});
            return nm.name;
        }

        // MX (15): preference + exchange
        if (type === DNSMessage.RRType.MX) {
            const pref = readU16At(rdataStart);
            const nm = DNSMessage.readName(array, {off: rdataStart + 2});
            return {preference: pref, exchange: nm.name};
        }

        // SOA (6): mname, rname, serial, refresh, retry, expire, minimum
        if (type === DNSMessage.RRType.SOA) {
            let cursor = rdataStart;
            const m = DNSMessage.readName(array, {off: cursor});
            cursor = m.off;
            const r = DNSMessage.readName(array, {off: cursor});
            cursor = r.off;

            // Checks if there are enough bytes for the remaining fields
            if (cursor + lengthSOAMin > end) {
                return {mname: m.name, rname: r.name};
            }

            const serial = readU32At(cursor);
            cursor += 4;

            const refresh = readU32At(cursor);
            cursor += 4;

            const retry = readU32At(cursor);
            cursor += 4;

            const expire = readU32At(cursor);
            cursor += 4;

            const minimum = readU32At(cursor);

            return {
                mname: m.name, rname: r.name, serial, refresh, retry, expire, minimum
            };
        }

        // SRV (33): priority, weight, port, target
        if (type === DNSMessage.RRType.SRV) {
            if (rdataStart + lengthSRVMin > end) {
                return null;
            }

            const priority = readU16At(rdataStart);
            const weight = readU16At(rdataStart + 2);
            const port = readU16At(rdataStart + 4);
            const nm = DNSMessage.readName(array, {off: rdataStart + 6});
            return {priority, weight, port, target: nm.name};
        }

        // Default: keep as raw bytes (Uint8Array)
        return null;
    }

    /**
     * Reads a domain name from the DNS message byte array, handling compression.
     *
     * @param {Uint8Array} array - The byte array containing the DNS message.
     * @param {Object} state - An object containing the current offset in the byte array.
     * @param {number} state.off - The current offset in the byte array to start reading from.
     * @returns {{name: string|string, off: number|*}} - The domain name and the new offset.
     */
    static readName(array, state) {
        const maxJumps = 50;
        const maxLabels = 127;

        let off = state.off;
        const labels = [];

        let jumped = false;
        let jumpBack = -1;
        let jumps = 0;
        let labelCount = 0;

        while (true) {
            // Checks if the offset is within bounds
            if (off >= array.length) {
                throw new Error("Truncated DNS name.");
            }

            const len = array[off];

            // Checks if this is a compression pointer
            if ((len & 0xC0) === 0xC0) {
                if (off + 1 >= array.length) {
                    throw new Error("Truncated DNS compression pointer.");
                }

                const ptr = (len & 0x3F) << 8 | array[off + 1];

                if (!jumped) {
                    jumpBack = off + 2;
                    jumped = true;
                }

                off = ptr;
                jumps++;

                // Prevents infinite loops in case of malformed messages
                if (jumps > maxJumps) {
                    throw new Error("DNS name compression loop suspected.");
                }
                continue;
            }

            // End of the name
            if (len === 0) {
                off += 1;
                break;
            }

            // DNS label length limit is 63
            if (len > 63) {
                throw new Error("Invalid DNS label length.");
            }

            off += 1;

            // Checks if the label length exceeds the array bounds
            if (off + len > array.length) {
                throw new Error("Truncated DNS label.");
            }

            labels.push(String.fromCodePoint(...array.subarray(off, off + len)));
            off += len;
            labelCount++;

            // Prevents excessive label counts in case of malformed messages
            if (labelCount > maxLabels) {
                throw new Error("DNS name too long / malformed.");
            }
        }

        return {
            name: labels.length ? labels.join(".") : ".",
            off: jumped ? jumpBack : off
        };
    }

    /**
     * Normalizes a domain name for comparison.
     *
     * @param {string} name - The domain name to normalize.
     * @returns {string} - The normalized domain name.
     */
    static normalizeName(name) {
        if (typeof name !== 'string') {
            return "";
        }

        const normalized = name.trim().toLowerCase();

        if (normalized === ".") {
            return ".";
        }
        return normalized.endsWith(".") ? normalized.slice(0, -1) : normalized;
    }

    /**
     * Prints a human-readable representation of the DNS message, including header information and resource records.
     *
     * @param {Object} opts - Optional settings for printing the DNS message.
     * @param {boolean} opts.includeRawRdata - Whether to include the raw hex bytes of the RDATA for each RR (default: false).
     * @param {number} opts.maxRawBytes - The maximum number of raw bytes to include per RR when includeRawRdata is true (default: 64).
     * @param {function} opts.out - A custom output function to receive the formatted string (default: console.log).
     */
    print(opts = {}) {
        const {
            includeRawRdata = false,   // include hex bytes for each RR
            maxRawBytes = 64,          // cap raw dump length per RR
            out = console.log          // allow custom sink
        } = opts;

        const lines = [];

        // ----- header -----
        lines.push("=== DNSMessage ===",
            `ID: 0x${this.id.toString(16).padStart(4, "0")} (${this.id})`,
            `Flags: 0x${this.flags.toString(16).padStart(4, "0")}  ${DNSMessage.flagsToString(this.flags)}`,
            `Counts: QD=${this.qdCount}  AN=${this.anCount}  NS=${this.nsCount}  AR=${this.arCount}`,
            ``,
            `-- Questions (${this.questions.length}) --`
        );

        if (this.questions.length === 0) {
            lines.push("(none)");
        } else {
            this.questions.forEach((q, i) => {
                lines.push(
                    `${i + 1}. ${q.qname}  ${DNSMessage.typeToString(q.qtype)} (${q.qtype})  CLASS=${q.qclass}`
                );
            });
        }

        // ----- sections -----
        const dumpSection = (title, arr) => {
            lines.push(``,
                `-- ${title} (${arr.length}) --`
            );

            if (arr.length === 0) {
                lines.push("(none)");
                return;
            }

            arr.forEach((rr, i) => {
                lines.push(`${i + 1}. ${DNSMessage.formatRR(rr, {includeRawRdata, maxRawBytes})}`);
            });
        };

        dumpSection("Answers", this.answers);
        dumpSection("Authorities", this.authorities);
        dumpSection("Additionals", this.additionals);

        // Emit
        out(lines.join("\n"));
    }

    /**
     * Converts a DNS RR type code to a human-readable string.
     *
     * @param {number} type - The DNS RR type code to convert.
     * @returns {*|string} - The human-readable string representation of the DNS RR type.
     */
    static typeToString(type) {
        const map = DNSMessage.TypeName || (DNSMessage.TypeName = Object.fromEntries(
            Object.entries(DNSMessage.RRType).map(([k, v]) => [v, k])
        ));
        return map[type] || `TYPE${type}`;
    }

    /**
     * Converts a DNS RR class code to a human-readable string.
     *
     * @param {number} rrclass - The DNS RR class code to convert.
     * @returns {string} - The human-readable string representation of the DNS RR class.
     */
    static classToString(rrclass) {
        if (rrclass === 1) {
            return "IN";
        }
        return `CLASS${rrclass}`;
    }

    /**
     * Converts DNS header flags to a human-readable string representation.
     *
     * @param {number} flags - The 16-bit DNS header flags to convert.
     * @returns {string} - The human-readable string representation of the DNS header flags.
     */
    static flagsToString(flags) {
        // DNS header flags: QR(15) OPCODE(14..11) AA(10) TC(9) RD(8) RA(7) Z(6) AD(5) CD(4) RCODE(3..0)
        const QR = flags >>> 15 & 0x1;
        const OPCODE = flags >>> 11 & 0xF;
        const AA = flags >>> 10 & 0x1;
        const TC = flags >>> 9 & 0x1;
        const RD = flags >>> 8 & 0x1;
        const RA = flags >>> 7 & 0x1;
        const Z = flags >>> 6 & 0x1;
        const AD = flags >>> 5 & 0x1;
        const CD = flags >>> 4 & 0x1;
        const RCODE = flags & 0xF;

        const opcodeNames = {
            0: "QUERY",
            1: "IQUERY",
            2: "STATUS",
            4: "NOTIFY",
            5: "UPDATE"
        };

        const rcodeNames = {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED"
        };

        const parts = [];
        parts.push(QR ? "RESPONSE" : "QUERY", `OPCODE=${opcodeNames[OPCODE] ?? OPCODE}`);

        if (AA) {
            parts.push("AA");
        }

        if (TC) {
            parts.push("TC");
        }

        if (RD) {
            parts.push("RD");
        }

        if (RA) {
            parts.push("RA");
        }

        if (AD) {
            parts.push("AD");
        }

        if (CD) {
            parts.push("CD");
        }

        if (Z) {
            parts.push("Z");
        }

        parts.push(`RCODE=${rcodeNames[RCODE] ?? RCODE}`);
        return parts.join(" ");
    }

    /**
     * Formats a DNS Resource Record (RR) into a human-readable string representation, including optional raw RDATA bytes.
     *
     * @param {Object} rr - The DNS Resource Record (RR) to format, containing fields such as name, type, class, ttl, rdlength, rdata, and optionally rdataRaw.
     * @param {boolean} includeRawRdata - Whether to include the raw hex bytes of the RDATA in the formatted output (default: false).
     * @param {number} maxRawBytes - The maximum number of raw bytes to include in the formatted output when includeRawRdata is true (default: 64).
     * @returns {string} - The formatted string representation of the DNS Resource Record (RR).
     */
    static formatRR(rr, {includeRawRdata = false, maxRawBytes = 64} = {}) {
        const t = DNSMessage.typeToString(rr.type);
        const c = DNSMessage.classToString(rr.class);
        const header = `${rr.name}  ${rr.ttl}  ${c}  ${t}`;

        // Pretty RDATA
        let rdataStr;
        const r = rr.rdata;

        if (r === null) {
            rdataStr = "(unparsed)";
        } else if (typeof r === "string" || typeof r === "number") {
            rdataStr = String(r);
        } else if (rr.type === DNSMessage.RRType.MX && r && typeof r === "object") {
            rdataStr = `${r.preference} ${r.exchange}`;
        } else if (rr.type === DNSMessage.RRType.SRV && r && typeof r === "object") {
            rdataStr = `${r.priority} ${r.weight} ${r.port} ${r.target}`;
        } else if (rr.type === DNSMessage.RRType.SOA && r && typeof r === "object") {
            const tail = [
                r.serial, r.refresh, r.retry, r.expire, r.minimum
            ].every(v => v !== undefined) ? ` ${r.serial} ${r.refresh} ${r.retry} ${r.expire} ${r.minimum}` : "";

            rdataStr = `${r.mname} ${r.rname}${tail}`;
        } else {
            // generic object
            rdataStr = JSON.stringify(r);
        }

        const bits = [`${header}  ${rdataStr}`, `(rdlength=${rr.rdlength})`];

        if (includeRawRdata && rr.rdataRaw) {
            const raw = rr.rdataRaw;
            const slice = raw.subarray(0, Math.min(raw.length, maxRawBytes));
            const hex = Array.from(slice, b => b.toString().padStart(2, "0")).join(" ");
            const suffix = raw.length > slice.length ? ` …(+${raw.length - slice.length} bytes)` : "";
            bits.push(`raw: ${hex}${suffix}`);
        }
        return bits.join("  ");
    }
}

DNSMessage.RRType = {
    A: 1,
    NS: 2,
    CNAME: 5,
    SOA: 6,
    PTR: 12,
    MX: 15,
    AAAA: 28,
    SRV: 33
};

DNSMessage.OPCODE = {
    QUERY: 0,
    IQUERY: 1,
    STATUS: 2,
    NOTIFY: 4,
    UPDATE: 5
};

DNSMessage.RCODE = {
    NOERROR: 0,
    FORMERR: 1,
    SERVFAIL: 2,
    NXDOMAIN: 3,
    NOTIMP: 4,
    REFUSED: 5
};
