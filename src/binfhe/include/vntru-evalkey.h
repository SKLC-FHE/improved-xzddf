//wkx
#ifndef _VNTRU_EVAL_KEY_H_
#define _VNTRU_EVAL_KEY_H_

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-privatekey.h"
#include "lwe-cryptoparameters.h"

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>


namespace lbcrypto {

class VectorNTRUEvalKeyImpl;
using VectorNTRUEvalKey      = std::shared_ptr<VectorNTRUEvalKeyImpl>;
using ConstVectorNTRUEvalKey = const std::shared_ptr<const VectorNTRUEvalKeyImpl>;


class VectorNTRUEvalKeyImpl : public Serializable {
private:
    std::vector<NativePoly> m_elements;
public:
/*-------------类初始化--------------------*/
    VectorNTRUEvalKeyImpl() = default;

    VectorNTRUEvalKeyImpl(uint32_t colSize) noexcept
        : m_elements(std::vector<NativePoly>(colSize)) {}

    explicit VectorNTRUEvalKeyImpl(const std::vector<NativePoly>& elements) : m_elements(elements) {}

    VectorNTRUEvalKeyImpl(const VectorNTRUEvalKeyImpl& rhs) : m_elements(rhs.m_elements) {}

    VectorNTRUEvalKeyImpl(VectorNTRUEvalKeyImpl&& rhs) noexcept : m_elements(std::move(rhs.m_elements)) {}

    VectorNTRUEvalKeyImpl& operator=(const VectorNTRUEvalKeyImpl& rhs) {
        VectorNTRUEvalKeyImpl::m_elements = rhs.m_elements;
        return *this;
    }

    VectorNTRUEvalKeyImpl& operator=(VectorNTRUEvalKeyImpl&& rhs) noexcept {
        VectorNTRUEvalKeyImpl::m_elements = std::move(rhs.m_elements);
        return *this;
    }

    const std::vector<NativePoly>& GetElements() const {
        return m_elements;
    }

    void SetElements(const std::vector<NativePoly>& elements) {
        m_elements = elements;
    }

    /**
   * Switches between COEFFICIENT and Format::EVALUATION polynomial
   * representations using NTT
   */
    void SetFormat(const Format format) {
     
            auto& l1 = m_elements;
            for (size_t j = 0; j < l1.size(); ++j){
                l1[j].SetFormat(format);
        }
    }

    NativePoly& operator[](uint32_t i) {
        return m_elements[i];
    }

    const NativePoly& operator[](uint32_t i) const {
        return m_elements[i];
    }

    bool operator==(const VectorNTRUEvalKeyImpl& other) const {
        if (m_elements.size() != other.m_elements.size())
            return false;
        return true;
    }

    bool operator!=(const VectorNTRUEvalKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("elements", m_elements));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("elements", m_elements));
    }

    std::string SerializedObjectName() const override {
        return "VectorNTRUEvalKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }


};

} // namespace lbcrypto

#endif  // _VNTRU_EVAL_KEY_H_