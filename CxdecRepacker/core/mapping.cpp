#include "core/mapping.h"

#include <cstring>

namespace hxv4 {

uint64_t MappingRecord::domain_hash_value() const {
    uint64_t v = 0;
    for (const uint8_t b : domain_hash_bytes) v = (v << 8) | b;
    return v;
}

bool mapping_parse(const uint8_t* data, size_t len, MappingTable& out) {
    TjsValue root;
    if (!tjs_parse(data, len, root)) return false;
    if (root.type != TjsType::Array) return false;

    const std::vector<TjsValue>& top = root.array;
    if (top.size() % 2 != 0) return false;

    out.records.clear();
    for (size_t i = 0; i + 1 < top.size(); i += 2) {
        const TjsValue& domain = top[i];
        const TjsValue& group = top[i + 1];
        if (!domain.is_octet() || domain.octet.size() != 8) return false;
        if (group.type != TjsType::Array) return false;
        if (group.array.size() % 2 != 0) return false;

        for (size_t j = 0; j + 1 < group.array.size(); j += 2) {
            const TjsValue& file_hash = group.array[j];
            const TjsValue& entry = group.array[j + 1];
            if (!file_hash.is_octet() || file_hash.octet.size() != 32) return false;
            if (entry.type != TjsType::Array || entry.array.size() != 2) return false;
            if (!entry.array[0].is_int() || !entry.array[1].is_int()) return false;

            MappingRecord rec;
            std::memcpy(rec.domain_hash_bytes.data(), domain.octet.data(),
                        rec.domain_hash_bytes.size());
            std::memcpy(rec.file_hash.data(), file_hash.octet.data(), rec.file_hash.size());
            rec.packed = static_cast<uint32_t>(entry.array[0].integer);
            rec.key = static_cast<uint64_t>(entry.array[1].integer);
            out.records.push_back(rec);
        }
    }
    return true;
}

std::vector<uint8_t> mapping_serialize(const MappingTable& table) {
    TjsValue root;
    root.type = TjsType::Array;

    size_t i = 0;
    while (i < table.records.size()) {
        const MappingRecord& first = table.records[i];

        TjsValue domain;
        domain.type = TjsType::Octet;
        domain.octet.assign(first.domain_hash_bytes.begin(), first.domain_hash_bytes.end());

        TjsValue group;
        group.type = TjsType::Array;
        size_t j = i;
        while (j < table.records.size() &&
               table.records[j].domain_hash_bytes == first.domain_hash_bytes) {
            const MappingRecord& rec = table.records[j];

            TjsValue file_hash;
            file_hash.type = TjsType::Octet;
            file_hash.octet.assign(rec.file_hash.begin(), rec.file_hash.end());

            TjsValue packed;
            packed.type = TjsType::Int;
            packed.integer = static_cast<int64_t>(static_cast<int32_t>(rec.packed));

            TjsValue key;
            key.type = TjsType::Int;
            key.integer = static_cast<int64_t>(rec.key);

            TjsValue entry;
            entry.type = TjsType::Array;
            entry.array.push_back(std::move(packed));
            entry.array.push_back(std::move(key));

            group.array.push_back(std::move(file_hash));
            group.array.push_back(std::move(entry));
            ++j;
        }

        root.array.push_back(std::move(domain));
        root.array.push_back(std::move(group));
        i = j;
    }

    return tjs_serialize(root);
}

}  // namespace hxv4
