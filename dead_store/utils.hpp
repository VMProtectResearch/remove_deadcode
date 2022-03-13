#pragma once
#include<fstream>
#include<vector>

#include<Zydis/Utils.h>
#include<Zydis/Zydis.h>

struct ZYDIS_INSN_INFO {
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
    std::uintptr_t addr;
    ZYDIS_INSN_INFO(ZydisDecodedInstruction instr, ZydisDecodedOperand* operands, uintptr_t addr)
    {
        this->instr = instr;
        this->addr = addr;
        memcpy(this->operands, operands, sizeof(ZydisDecodedOperand));
    }
    //ZYDIS_INSN_INFO(const ZYDIS_INSN_INFO&)
    //{
        //memcpy(this->operands, operands, sizeof(operands));
    //}
};
using ZYDIS_ROUTINUE = std::vector<ZYDIS_INSN_INFO>;

namespace utils {

    inline thread_local std::shared_ptr<ZydisDecoder> g_decoder = nullptr;
    inline thread_local std::shared_ptr<ZydisFormatter> g_formatter = nullptr;
    
    inline void init() {
        if (!g_decoder && !g_formatter) {
            g_decoder = std::make_shared<ZydisDecoder>();
            g_formatter = std::make_shared<ZydisFormatter>();

            ZydisDecoderInit(g_decoder.get(), ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64);

            ZydisFormatterInit(g_formatter.get(),
                ZYDIS_FORMATTER_STYLE_INTEL);
        }
    }


    inline bool open_binary_file(const std::string& file,
        std::vector<uint8_t>& data) {
        std::ifstream fstr(file, std::ios::binary);
        if (!fstr.is_open()) return false;

        fstr.unsetf(std::ios::skipws);
        fstr.seekg(0, std::ios::end);

        const auto file_size = fstr.tellg();

        fstr.seekg(NULL, std::ios::beg);
        data.reserve(static_cast<uint32_t>(file_size));
        data.insert(data.begin(), std::istream_iterator<uint8_t>(fstr),
            std::istream_iterator<uint8_t>());
        return true;
    }

    void print(const ZydisDecodedInstruction& instr) {
        char buffer[256];
        ZydisFormatterFormatInstruction(g_formatter.get(), &instr, 0,0,buffer,
            sizeof(buffer), 0u);
        std::puts(buffer);
    }

    void print(ZYDIS_ROUTINUE& routine) {
        char buffer[256];
        for (auto [instr,operands,addr] : routine) {
            ZydisFormatterFormatInstruction(g_formatter.get(), &instr, operands, instr.operand_count_visible,buffer,
                sizeof(buffer), addr);
            std::printf("> %p %s\n", addr, buffer);
        }
    }

    bool is_jcc(const ZydisDecodedInstruction& instr) {
        return instr.mnemonic >= ZYDIS_MNEMONIC_JB &&
            instr.mnemonic <= ZYDIS_MNEMONIC_JZ;
    }

    bool is_jmp(const ZydisDecodedInstruction& instr)
    {
        return instr.mnemonic == ZYDIS_MNEMONIC_JMP;
    }



}