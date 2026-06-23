// =============================================================================
// pcap_reader.cpp — Implementation of PcapReader and PcapWriter
// =============================================================================

#include "pcap_reader.h"
#include <cstring>
#include <sstream>
#include <stdexcept>

// =============================================================================
// PcapReader
// =============================================================================

void PcapReader::open(const std::string& filename) {
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        throw std::runtime_error("PcapReader: cannot open file: " + filename);
    }

    // Read global header (24 bytes)
    if (!file_.read(reinterpret_cast<char*>(&global_hdr_), sizeof(PcapGlobalHeader))) {
        throw std::runtime_error("PcapReader: file too small to contain PCAP global header");
    }

    // Validate magic number — detect byte order
    if (global_hdr_.magic_number == PCAP_MAGIC_NATIVE ||
        global_hdr_.magic_number == PCAP_MAGIC_NSEC) {
        byte_swapped_ = false;
    } else if (global_hdr_.magic_number == PCAP_MAGIC_SWAPPED) {
        byte_swapped_ = true;
        // Fix up the rest of the global header
        global_hdr_.version_major = fixU16(global_hdr_.version_major);
        global_hdr_.version_minor = fixU16(global_hdr_.version_minor);
        global_hdr_.snaplen       = fixU32(global_hdr_.snaplen);
        global_hdr_.network       = fixU32(global_hdr_.network);
    } else {
        std::ostringstream ss;
        ss << "PcapReader: invalid magic number 0x"
           << std::hex << global_hdr_.magic_number
           << " — not a valid PCAP file";
        throw std::runtime_error(ss.str());
    }

    // We support only Ethernet (link type 1)
    // Allow link type 0 (null/loopback) and 101 (raw IP) as fallback for some captures
    if (global_hdr_.network != PCAP_LINK_ETHERNET &&
        global_hdr_.network != 0 &&
        global_hdr_.network != 101) {
        // Don't throw — warn but continue; parser will handle gracefully
    }
}

bool PcapReader::readNextPacket(RawPacket& raw) {
    if (!file_.is_open()) return false;

    // Read 16-byte packet header
    if (!file_.read(reinterpret_cast<char*>(&raw.header), sizeof(PcapPacketHeader))) {
        return false;  // EOF
    }

    // Fix byte order if needed
    raw.header.ts_sec   = fixU32(raw.header.ts_sec);
    raw.header.ts_usec  = fixU32(raw.header.ts_usec);
    raw.header.incl_len = fixU32(raw.header.incl_len);
    raw.header.orig_len = fixU32(raw.header.orig_len);

    // Sanity check: incl_len should not exceed snaplen or some sane maximum
    // (65535 bytes is the standard PCAP max)
    constexpr uint32_t MAX_PACKET_SIZE = 65536;
    if (raw.header.incl_len > MAX_PACKET_SIZE) {
        throw std::runtime_error(
            "PcapReader: packet incl_len=" + std::to_string(raw.header.incl_len) +
            " exceeds maximum — PCAP file may be corrupt");
    }

    // Read packet data
    raw.data.resize(raw.header.incl_len);
    if (raw.header.incl_len > 0) {
        if (!file_.read(reinterpret_cast<char*>(raw.data.data()), raw.header.incl_len)) {
            throw std::runtime_error("PcapReader: unexpected end of file reading packet data");
        }
    }

    ++packets_read_;
    return true;
}

void PcapReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
}

// =============================================================================
// PcapWriter
// =============================================================================

void PcapWriter::open(const std::string& filename, uint32_t snaplen, uint32_t link_type) {
    file_.open(filename, std::ios::binary | std::ios::trunc);
    if (!file_.is_open()) {
        throw std::runtime_error("PcapWriter: cannot create file: " + filename);
    }

    // Write PCAP global header in native byte order
    PcapGlobalHeader hdr{};
    hdr.magic_number  = PCAP_MAGIC_NATIVE;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone      = 0;
    hdr.sigfigs       = 0;
    hdr.snaplen       = snaplen;
    hdr.network       = link_type;

    if (!file_.write(reinterpret_cast<const char*>(&hdr), sizeof(PcapGlobalHeader))) {
        throw std::runtime_error("PcapWriter: failed to write global header");
    }
}

void PcapWriter::writePacket(const PcapPacketHeader& hdr, const uint8_t* data, uint32_t len) {
    // Write packet header (16 bytes)
    if (!file_.write(reinterpret_cast<const char*>(&hdr), sizeof(PcapPacketHeader))) {
        throw std::runtime_error("PcapWriter: failed to write packet header");
    }
    // Write packet data
    if (len > 0 && data != nullptr) {
        if (!file_.write(reinterpret_cast<const char*>(data), len)) {
            throw std::runtime_error("PcapWriter: failed to write packet data");
        }
    }
    ++packets_written_;
}

void PcapWriter::writePacket(const RawPacket& raw) {
    writePacket(raw.header, raw.data.data(), raw.header.incl_len);
}

void PcapWriter::writePacket(const Packet& pkt) {
    writePacket(pkt.pcap_hdr, pkt.data.data(),
                static_cast<uint32_t>(pkt.data.size()));
}

void PcapWriter::close() {
    if (file_.is_open()) {
        file_.flush();
        file_.close();
    }
}
