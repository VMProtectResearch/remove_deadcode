﻿#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>

#include "../cmdline-parser/parse.hpp"
#include "utils.hpp"

using namespace std;

int main(int argc,char* argv[])
{
   string bin_path = cmd::parse(argc,argv,"-bin");
   uint32_t rva = stoul(cmd::parse(argc, argv, "-rva"),0,16);
   vector<uint8_t> bin_data;
   uint64_t module_base;
   ZydisDecodedInstruction instr;
   ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
   uint32_t max_instrs = 0;
   ZYDIS_ROUTINUE zydis_routinue;
   uint64_t routine_addr;

   if (!(module_base = (uint64_t)LoadLibraryExA(bin_path.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES)))
   {
       cout << "bin is invaild\n";
       return 0;
   }

   if (!rva)
   {
       cout << "rva is invaild\n";
       return 0;
   }

   routine_addr = module_base + rva;

   //init zydis
   utils::init();
   while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
       utils::g_decoder.get(),(void*)routine_addr, 0x1000,
       &instr, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
   {
       max_instrs++;
       if (max_instrs > 500)
           break;

       zydis_routinue.emplace_back( instr, operands,routine_addr ); //对routine_addr反汇编

       if (utils::is_jcc(instr)) 
       {
           if (utils::is_jmp(instr)) //如果是jmp的话,改变反汇编起始地址
           {
               ZyanU64 abs_addr;
               ZydisCalcAbsoluteAddress(&instr, operands, routine_addr, &abs_addr);
               routine_addr = abs_addr;
           }
           else //其他的条件jcc,dead store不负责这一块
               break;
       }else
           routine_addr += instr.length; //移动到下一条指令

   }

   //utils::print(zydis_routinue);

   utils::optimize::remove_dead_store(zydis_routinue);


   return 0;
}

