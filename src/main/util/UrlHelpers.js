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

// Object containing helper functions for working with URLs
const UrlHelpers = (() => {

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = globalThis.chrome ?? globalThis.browser;

    // Base URL for the block page
    const blockPageBaseUrl = browserAPI.runtime.getURL("pages/warning/WarningPage.html");

    /**
     * Extracts the blocked URL (the website being reported as malicious) from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the blocked website information.
     * @returns {string|null} - The blocked URL, or null if not found.
     */
    const extractBlockedUrl = url => {
        try {
            return new URL(url).searchParams.get("url");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return null;
        }
    };

    /**
     * Extracts the continue URL from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the continue URL parameter.
     * @returns {string|null} - The continue URL, or null if not found.
     */
    const extractContinueUrl = url => {
        try {
            return new URL(url).searchParams.get("curl");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return null;
        }
    };

    /**
     * Extracts the origin of the protection result from the query parameters of a URL.
     *
     * @param url - The URL containing the origin information
     * @returns {string} - The origin of the protection result
     */
    const extractOrigin = url => {
        try {
            return new URL(url).searchParams.get("or");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return "0";
        }
    };

    /**
     * Extracts the result (e.g., phishing, malware) from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the result.
     * @returns {string|null} - The result from the URL, or null if not found.
     */
    const extractResult = url => {
        try {
            return new URL(url).searchParams.get("rs");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return "0";
        }
    };

    /**
     * Constructs the URL for the browser's block page, which shows a warning when a website is blocked.
     *
     * @param {object} protectionResult - The result object containing details about the threat.
     * @param {object} continueURL - The URL to continue to if the user clicks a continue button.
     * @returns {string} - The full URL for the block page.
     */
    const getBlockPageUrl = (protectionResult, continueURL) => {
        // Checks if the protection result is valid
        if (!protectionResult || typeof protectionResult !== 'object') {
            throw new Error('Invalid protection result');
        }

        // Checks if the protection result's properties are valid
        if (!protectionResult.url || !protectionResult.origin || !protectionResult.resultType) {
            throw new Error('Missing required protection result properties');
        }

        try {
            // Constructs a new URL object for the block page
            const blockPageUrl = new URL(blockPageBaseUrl);

            // Sets the search parameters for the block page URL
            blockPageUrl.search = new URLSearchParams([
                ["url", protectionResult.url],       // The URL of the blocked website
                ["curl", continueURL || ''],         // The continue URL
                ["or", protectionResult.origin],     // The origin of the protection result
                ["rs", protectionResult.resultType]  // The result type
            ]).toString();

            // Returns the constructed block page URL as a string
            return blockPageUrl.toString();
        } catch (error) {
            throw new Error(`Failed to construct block page URL: ${error.message}`);
        }
    };

    /**
     * Normalizes an IP address.
     *
     * @param {string} hostname - The IP/hostname to check.
     * @returns {null|string} - The normalized IP address.
     */
    const normalizeIP = hostname => {
        let s = (hostname || "").trim().toLowerCase();

        // Strip brackets and zone/scope id (e.g., %eth0)
        if (s.startsWith("[") && s.endsWith("]")) {
            s = s.slice(1, -1);
        }

        const pct = s.indexOf("%");

        // Remove zone index
        if (pct !== -1) {
            s = s.slice(0, pct);
        }

        // IPv4 dotted-decimal only
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
            const nums = s.split('.').map(Number);

            // Each number must be between 0 and 255
            if (nums.some(n => n < 0 || n > 255)) {
                return null;
            }
            return nums.join('.');
        }

        // Minimal IPv6 acceptance (including IPv4-mapped tails)
        if (s.includes(":")) {
            // Allow hex, colons, and optional dotted tail; reject other chars
            if (!/^[0-9a-f:.\s]+$/.test(s)) {
                return null;
            }

            const lastColon = s.lastIndexOf(":");

            // If IPv4 tail exists, ensure it's a valid dotted-decimal
            if (s.includes(".") && lastColon !== -1) {
                const tail = s.slice(lastColon + 1);

                // Basic dotted-decimal check
                if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(tail)) {
                    return null;
                }

                const nums = tail.split(".").map(Number);

                // Each number must be between 0 and 255
                if (nums.some(n => n < 0 || n > 255)) {
                    return null;
                }
            }

            // Basic shape check: at least one colon, not more than 7 colon separators unless compressed
            // (We’re intentionally permissive; detailed parsing would add complexity.)
            return s;
        }
        return null;
    };

    /**
     * Checks if a hostname is locally hosted.
     *
     * @param hostname - The hostname to check.
     * @returns {boolean|boolean} - If a hostname is locally hosted.
     */
    const isLocalHostname = hostname => {
        let h = (hostname || "").trim().toLowerCase();

        // Strip brackets and zone/scope id for IPv6 literals
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.slice(1, -1);
        }

        const pct = h.indexOf("%");

        // Remove zone index
        if (pct !== -1) {
            h = h.slice(0, pct);
        }

        // localhost and .localhost/.local domains
        if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local")) {
            return true;
        }

        // IPv6 loopback/unspecified (compressed and full)
        if (h.includes(":")) {
            if (h === "::1" || h === "0:0:0:0:0:0:0:1") {
                return true;
            }
            return h === "::" || h === "0:0:0:0:0:0:0:0";
        }

        // IPv4 loopback/unspecified
        const ip = normalizeIP(h);
        return ip ? ip.startsWith("127.") || ip === "0.0.0.0" : false;
    };

    /**
     * Checks if an IP address is private/locally hosted.
     *
     * @param ip - The IP address to check.
     * @returns {boolean|boolean|boolean} - If the IP address is private/locally hosted.
     */
    const isPrivateIP = ip => {
        let s = (ip || "").trim().toLowerCase();

        // Strip brackets and zone/scope id for IPv6 literals
        if (s.startsWith("[") && s.endsWith("]")) {
            s = s.slice(1, -1);
        }

        const pct = s.indexOf("%");

        // Remove zone index
        if (pct !== -1) {
            s = s.slice(0, pct);
        }

        // IPv6 ranges
        if (s.includes(":")) {
            // Loopback / unspecified
            if (s === "::1" || s === "0:0:0:0:0:0:0:1") {
                return true;
            }
            if (s === "::" || s === "0:0:0:0:0:0:0:0") {
                return true;
            }

            // ULA fc00::/7
            if (s.startsWith("fc") || s.startsWith("fd")) {
                return true;
            }

            // Link-local fe80::/10
            if (/^fe([89ab])[0-9a-f]{2}:/i.test(s)) {
                return true;
            }

            // IPv4-mapped ::ffff:a.b.c.d
            if (s.startsWith("::ffff:")) {
                const v4 = s.slice(7);
                const v4n = normalizeIP(v4);

                if (!v4n) {
                    return false;
                }

                return v4n.startsWith("127.") ||               // loopback
                    v4n.startsWith("10.") ||                // 10/8
                    /^172\.(1[6-9]|2\d|3[0-1])\./.test(v4n) || // 172.16/12
                    v4n.startsWith("192.168.") ||           // 192.168/16
                    v4n.startsWith("169.254.") ||           // link-local
                    v4n === "0.0.0.0";                      // unspecified
            }
            return false;
        }

        // IPv4 ranges
        const v4n = normalizeIP(s);
        return v4n ? v4n.startsWith("127.") ||
            v4n.startsWith("10.") ||
            /^172\.(1[6-9]|2\d|3[0-1])\./.test(v4n) ||
            v4n.startsWith("192.168.") ||
            v4n.startsWith("169.254.") ||
            v4n === "0.0.0.0" : false;
    };

    /**
     * Checks if a hostname/IP address is locally hosted.
     *
     * @param hostname - The hostname to check.
     * @returns {boolean} - If a hostname is locally hosted.
     */
    const isInternalAddress = hostname => {
        if (isLocalHostname(hostname)) {
            return true;
        }

        let h = (hostname || "").trim().toLowerCase();

        // Strip brackets and zone/scope id for IPv6 literals
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.slice(1, -1);
        }

        const pct = h.indexOf("%");

        // Remove zone index
        if (pct !== -1) {
            h = h.slice(0, pct);
        }

        // IPv6 checks
        if (h.includes(":")) {
            // :: or ::1 handled by isLocalHostname; cover ULA/link-local here
            // ULA fc00::/7 => prefixes "fc" or "fd"
            if (h.startsWith("fc") || h.startsWith("fd")) {
                return true;
            }

            // Link-local fe80::/10 => fe80..febf (quick prefix test)
            if (/^fe([89ab])[0-9a-f]{2}:/i.test(h)) {
                return true;
            }

            // IPv4-mapped ::ffff:a.b.c.d -> check embedded IPv4 range
            if (h.startsWith("::ffff:")) {
                const v4 = h.slice(7);
                const v4n = normalizeIP(v4);
                return v4n ? isPrivateIP(v4n) : false;
            }
            return false;
        }

        // IPv4 checks
        const ip = normalizeIP(h); // IPv4 or simple IPv6 normalization
        return ip ? isPrivateIP(ip) : false;
    };

    /**
     * Normalizes a URL by removing the trailing slash and normalizing the hostname.
     *
     * @param url {string|URL} - The URL to normalize, can be a string or a URL object.
     * @returns {string|string} - The normalized URL as a string.
     */
    const normalizeUrl = url => {
        const u = typeof url === "string" ? new URL(url) : url;

        // Removes trailing dots from the hostname
        const host = u.hostname.toLowerCase().replace(/\.$/, '');

        // Removes trailing slashes from the pathname
        const path = u.pathname.replace(/\/+$/, '');
        return host + path;
    };

    /**
     * Encodes a DNS query for the given domain and type.
     *
     * @param {string} domain - The domain to encode.
     * @param {number} type - The type of DNS record (default is 1 for A record).
     * @return {string} - The base64url encoded DNS query.
     */
    const encodeDNSQuery = (domain, type = 1) => {
        if (typeof domain !== 'string') {
            throw new TypeError('domain must be a string');
        }

        // Strip trailing dot; DNS wire format carries labels explicitly
        const stripped = domain.trim().replace(/\.$/, '');

        const header = new Uint8Array([
            0x00, 0x00, // ID
            0x01, 0x00, // flags: standard query, recursion desired
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00  // ARCOUNT
        ]);

        const qname = [];

        for (const label of stripped.split('.')) {
            const bytes = new TextEncoder().encode(label);

            if (bytes.length === 0 || bytes.length > 63) {
                throw new Error(`Invalid label length in domain ${stripped}: ${bytes.length}`);
            }

            qname.push(bytes.length, ...bytes);
        }

        qname.push(0x00); // end of QNAME

        const qtype = new Uint8Array([type >>> 8 & 0xff, type & 0xff]);
        const qclass = new Uint8Array([0x00, 0x01]); // IN
        const packet = new Uint8Array(header.length + qname.length + qtype.length + qclass.length);

        packet.set(header, 0);
        packet.set(qname, header.length);
        packet.set(qtype, header.length + qname.length);
        packet.set(qclass, header.length + qname.length + qtype.length);

        let bin = '';

        for (const byte of packet) {
            bin += String.fromCodePoint(byte);
        }
        return btoa(bin).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
    };

    return {
        extractBlockedUrl,
        extractContinueUrl,
        extractOrigin,
        extractResult,
        normalizeUrl,
        getBlockPageUrl,
        isInternalAddress,
        encodeDNSQuery
    };
})();
