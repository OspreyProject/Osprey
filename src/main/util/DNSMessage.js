class DNSMessage {

    constructor() {
        this.id = 0;
        this.flags = 0;
        this.qdCount = 0;
        this.anCount = 0;
        this.nsCount = 0;
        this.arCount = 0;

        this.questions = [];   // { qname, qtype, qclass }
        this.answers = [];     // RR[]
        this.authorities = []; // RR[]
        this.additionals = []; // RR[]
    }

    qr() {
        return this.flags >>> 15 & 0x1;
    }

    opcode() {
        return this.flags >>> 11 & 0xF;
    }

    aa() {
        return this.flags >>> 10 & 0x1;
    }

    tc() {
        return this.flags >>> 9 & 0x1;
    }

    rd() {
        return this.flags >>> 8 & 0x1;
    }

    ra() {
        return this.flags >>> 7 & 0x1;
    }

    z() {
        return this.flags >>> 6 & 0x1;
    }

    ad() {
        return this.flags >>> 5 & 0x1;
    }

    cd() {
        return this.flags >>> 4 & 0x1;
    }

    rcode() {
        return this.flags & 0xF;
    }

    hasAdditional() {
        return this.additionals.length > 0;
    }

    hasAnswers() {
        return this.answers.length > 0;
    }

    hasAuthorities() {
        return this.authorities.length > 0;
    }

    hasRRType(type) {
        return this.sectionHasType(this.answers, type) ||
            this.sectionHasType(this.authorities, type) ||
            this.sectionHasType(this.additionals, type);
    }

    hasAdditionalRRType(type) {
        return this.sectionHasType(this.additionals, type);
    }

    sectionHasType(section, type) {
        return section.some(rr => rr.type === type);
    }

    /**
     * Checks whether any RR (in any section) contains the provided domain name
     * either as the RR owner name OR inside the RDATA for name-bearing types
     * (CNAME/NS/PTR/MX/SOA and a few others).
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
     * @param bytes - The byte array representing the DNS message.
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
     * @param array - The Uint8Array representing the DNS message.
     * @param type - The RR type.
     * @param rdataStart - The starting offset of the RDATA in the array.
     * @param rdlength - The length of the RDATA.
     */
    static parseRData(array, type, rdataStart, rdlength) {
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
            return parts.join(":").replace(/(^|:)0(:0)+(:|$)/, "::");
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
     * @param array - The Uint8Array representing the DNS message.
     * @param state - An object with the current offset: { off: number }.
     * @returns {{name: string|string, off: number|*}} - The domain name and the new offset.
     */
    static readName(array, state) {
        let off = state.off;
        const labels = [];

        let jumped = false;
        let jumpBack = -1;
        let steps = 0;

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
                steps++;

                // Prevent excessively many jumps
                const maxSteps = 50;
                if (steps > maxSteps) {
                    throw new Error("DNS name compression loop suspected.");
                }
                continue;
            }

            // End of the name
            if (len === 0) {
                off += 1;
                break;
            }

            off += 1;

            // Checks if the label length exceeds the array bounds
            if (off + len > array.length) {
                throw new Error("Truncated DNS label.");
            }

            const labelBytes = array.subarray(off, off + len);
            const label = String.fromCodePoint(...labelBytes);

            labels.push(label);

            off += len;
            steps++;

            // Prevents excessively long names
            const maxSteps = 200;
            if (steps > maxSteps) {
                throw new Error("DNS name too long / malformed.");
            }
        }

        const name = labels.length ? labels.join(".") : ".";

        return {
            name,
            off: jumped ? jumpBack : off
        };
    }

    /**
     * Normalizes a domain name for comparison.
     *
     * @param name - The domain name to normalize.
     * @returns {string} - The normalized domain name.
     */
    static normalizeName(name) {
        if (!name) {
            return "";
        }

        const normalized = name.trim().toLowerCase();

        if (normalized === ".") {
            return ".";
        }
        return normalized.endsWith(".") ? normalized.slice(0, -1) : normalized;
    }

    print(opts = {}) {
        const {
            includeRawRdata = false,   // include hex bytes for each RR
            maxRawBytes = 64,          // cap raw dump length per RR
            out = console.log          // allow custom sink
        } = opts;

        const lines = [];

        // ----- header -----
        lines.push("=== DNSMessage ===");
        lines.push(`ID: 0x${this.id.toString(16).padStart(4, "0")} (${this.id})`);
        lines.push(`Flags: 0x${this.flags.toString(16).padStart(4, "0")}  ${DNSMessage.flagsToString(this.flags)}`);
        lines.push(
            `Counts: QD=${this.qdCount}  AN=${this.anCount}  NS=${this.nsCount}  AR=${this.arCount}`
        );

        // ----- questions -----
        lines.push("");
        lines.push(`-- Questions (${this.questions.length}) --`);
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
            lines.push("");
            lines.push(`-- ${title} (${arr.length}) --`);
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

    static typeToString(type) {
        const map = DNSMessage.TypeName || (DNSMessage.TypeName = Object.fromEntries(
            Object.entries(DNSMessage.RRType).map(([k, v]) => [v, k])
        ));
        return map[type] || `TYPE${type}`;
    }

    static classToString(rrclass) {
        if (rrclass === 1) {
            return "IN";
        }
        return `CLASS${rrclass}`;
    }

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
            // (others exist; leave numeric if unknown)
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

    static formatRR(rr, {includeRawRdata = false, maxRawBytes = 64} = {}) {
        const t = DNSMessage.typeToString(rr.type);
        const c = DNSMessage.classToString(rr.class);
        const header = `${rr.name}  ${rr.ttl}  ${c}  ${t}`;

        // Pretty RDATA
        let rdataStr = "";
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
