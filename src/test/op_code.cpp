// Copyright (c) 2011-2018 The Bitcoin Cash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/script.h"
#include "script/interpreter.h"
#include "policy/policy.h"
#include <boost/test/unit_test.hpp>
#include <cassert>

using namespace std;

#ifdef VERBOSE
#undef VERBOSE
#endif

//--------------------------
//uncomment the following line to see debug output
#define VERBOSE
//--------------------------

#ifdef VERBOSE
#include <iostream>
#include <iomanip>
#include "core_io.h"
#endif

// temp - while waiting to transfer to main branch
const uint32_t SCRIPT_ENABLE_MONOLITH_OPCODES = (1U << 18);

namespace {

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;

#ifdef VERBOSE
        void print(const valtype& i) {
            if (i.empty()) cout << "empty";
            bool first = true;
            for (auto& s : i) {
                if(first) { 
                    first = false;
                } else {
                    cout << ", ";
		}
                cout << "{" << hex << setw(2) << setfill('0') << (int) s << "}";
            }
        }
        void print(const stacktype& i) {
            cout << "{";
            for (auto& s:i) 
                print(s);
            cout << "}";
        }
#endif

std::array<uint32_t, 3> flagset{0, 
                                STANDARD_SCRIPT_VERIFY_FLAGS,
                                MANDATORY_SCRIPT_VERIFY_FLAGS};

static void CheckOpError(uint32_t flags, const stacktype &original_stack,
                         const CScript& script, ScriptError expected_error) {
    BaseSignatureChecker sigchecker;

    ScriptError err = SCRIPT_ERR_OK;
    stacktype stack{original_stack};
    bool r = EvalScript(stack, script,
                        flags | SCRIPT_ENABLE_MONOLITH_OPCODES, sigchecker,
                        &err);
    BOOST_CHECK(!r);
    BOOST_CHECK_EQUAL(err, expected_error);
}

static void CheckOpError(const stacktype &original_stack,
                         const CScript& script, ScriptError expected_error) {
    for (uint32_t flags : flagset) {
        CheckOpError(flags, original_stack, script, expected_error);
    }
}

static void CheckOpError(const valtype& a, const CScript& script,
                         ScriptError expected_error) {
    CheckOpError(stacktype{a}, script, expected_error);
}

static void CheckOpError(const valtype& a, const valtype& b, const CScript& script,
                         ScriptError expected_error) {
    CheckOpError(stacktype{a,b}, script, expected_error);
}

////////////////////// methods which expect success.

static void CheckOp(uint32_t flags, const stacktype original_stack, const CScript& script, 
                    const stacktype &expected_stack) {
    BaseSignatureChecker sigchecker;

    ScriptError err = SCRIPT_ERR_OK;
    stacktype stack{original_stack};
    bool r = EvalScript(stack, script,
                        flags | SCRIPT_ENABLE_MONOLITH_OPCODES, sigchecker,
                        &err);
    BOOST_CHECK(r);
#ifdef VERBOSE
    if(!r) {
        cout << "Expected stack:> "; 
        print(stacktype{expected_stack});
        cout << " <\nActual stack:> "; 
        print(stack);
        cout << " <\n";
    }
#endif
    BOOST_CHECK(stack == expected_stack);
}

static void CheckOp(const stacktype &original_stack, const CScript& script, 
                           const stacktype& expected_stack) {
    for (uint32_t flags : flagset) {
        CheckOp(flags, original_stack, script, expected_stack);
    }
}

static void CheckOp(const stacktype &original_stack, const CScript& script, 
                           const valtype &expected) {
    CheckOp(original_stack, script, stacktype{expected});
}

static void CheckOp(const valtype &a, const CScript& script, const valtype &expected) {
    CheckOp(stacktype{a}, script, expected);
}

static void CheckOp(const valtype &a, const valtype &b, const CScript& script,
                           const valtype &expected) {
    CheckOp(stacktype{a, b}, script, expected);
}

// Comment out if you want masses of debug information.
#undef VERBOSE

    /// Deepest sole function for testing expected errors
    /// Invokes the interpreter.
    void test(const CScript& script, stacktype stack, uint32_t flags, const ScriptError se) {
        #ifdef VERBOSE
            cout << "--------------" << endl;
            cout << "Checking script \"" << FormatScript(script) << "\" flags " << flags << endl;
            cout << "with input stack: " << endl;
            print(stack);
            cout << "expected error: " << se << endl;
        #endif
        ScriptError err=SCRIPT_ERR_OK;
        BaseSignatureChecker sigchecker;
        bool r=EvalScript(stack, script, flags, sigchecker, &err);
        BOOST_CHECK_EQUAL(r, false);
        #ifdef VERBOSE
            cout << "got error: " << err << " vs " << se << endl;
        #endif
        BOOST_CHECK_EQUAL(err==se, true);
    }

    /// Deepest sole function for testing expected returning stacks
    /// Invokes the interpreter.
    void test(const CScript& script, stacktype stack, uint32_t flags, stacktype expected) {
        #ifdef VERBOSE
            cout << "--------------" << endl;
            cout << "Checking script \"" << FormatScript(script) << "\" flags " << flags << endl;
            cout << "with input stack: " << endl;
            print(stack);
            cout << "expected output stack: " << endl;
            print(expected);
        #endif
        ScriptError err;
        BaseSignatureChecker sigchecker;
        bool r=EvalScript(stack, script, flags, sigchecker, &err);
        #ifdef VERBOSE
            cout << "got output stack: " << endl;
            print(stack);
        #endif
        BOOST_CHECK_EQUAL(r, true);
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack==expected, true);
    }

    /// OP_AND, OP_OR, OP_XOR common tests

    void test_bitwiseop(const CScript& script, uint32_t flags) {
        //number of inputs
        test(script,stacktype(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
        test(script,stacktype(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
        test(script,stacktype{{0x01}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);

        //where len(x1) == 0 == len(x2) the output will be an empty array.
        test(script,stacktype{{}, {}},flags,stacktype{{}});

        //operation fails when length of operands not equal
        test(script,stacktype{{0x01}, {}},flags,SCRIPT_ERR_INVALID_BITWISE_OPERATION);
        test(script,stacktype{{0x01, 0x01}, {}},flags,SCRIPT_ERR_INVALID_BITWISE_OPERATION);
        test(script,stacktype{{}, {0x01}},flags,SCRIPT_ERR_INVALID_BITWISE_OPERATION);
        test(script,stacktype{{}, {0x01, 0x01}},flags,SCRIPT_ERR_INVALID_BITWISE_OPERATION);
        test(script,stacktype{{0x01}, {0x01, 0x01}},flags,SCRIPT_ERR_INVALID_BITWISE_OPERATION);
        test(script,stacktype{{0x01, 0x01}, {0x01, 0x01, 0x01}},flags,SCRIPT_ERR_INVALID_BITWISE_OPERATION);
        test(script,stacktype{{0x01, 0x01}, {0x01}},flags,SCRIPT_ERR_INVALID_BITWISE_OPERATION);
        test(script,stacktype{{0x01, 0x01, 0x01}, {0x01, 0x01}},flags,SCRIPT_ERR_INVALID_BITWISE_OPERATION);
    }

    /// OP_AND tests

    void test_and(uint32_t flags) {
        CScript script;
        script << OP_AND;
        test_bitwiseop(script,flags);
        test(script,stacktype{{0x00}, {0x00}},flags,stacktype{{0x00}});
        test(script,stacktype{{0x00}, {0x01}},flags,stacktype{{0x00}});
        test(script,stacktype{{0x01}, {0x00}},flags,stacktype{{0x00}});
        test(script,stacktype{{0x01}, {0x01}},flags,stacktype{{0x01}});

        test(script,stacktype{{0x00, 0x00}, {0x00, 0x00}},flags,stacktype{{0x00, 0x00}});
        test(script,stacktype{{0x00, 0x00}, {0x01, 0x00}},flags,stacktype{{0x00, 0x00}});
        test(script,stacktype{{0x01, 0x00}, {0x00, 0x00}},flags,stacktype{{0x00, 0x00}});
        test(script,stacktype{{0x01, 0x00}, {0x01, 0x00}},flags,stacktype{{0x01, 0x00}});

        {
        valtype maxlenbin1(MAX_SCRIPT_ELEMENT_SIZE, 0x01);
        valtype maxlenbin2(MAX_SCRIPT_ELEMENT_SIZE, 0xF0);
        valtype maxlenbin3(MAX_SCRIPT_ELEMENT_SIZE, 0x01 & 0xF0);
        test(script,stacktype{maxlenbin1,maxlenbin2},flags,stacktype{maxlenbin3});
        }

        {
        valtype maxlenbin1(MAX_SCRIPT_ELEMENT_SIZE, 0x3C);
        valtype maxlenbin2(MAX_SCRIPT_ELEMENT_SIZE, 0xDB);
        valtype maxlenbin3(MAX_SCRIPT_ELEMENT_SIZE, 0x3C & 0xDB);
        test(script,stacktype{maxlenbin1,maxlenbin2},flags,stacktype{maxlenbin3});
        }
    }

    /// OP_OR tests

    void test_or(uint32_t flags) {
        CScript script;
        script << OP_OR;
        test_bitwiseop(script,flags);

        test(script,stacktype{{0x00}, {0x00}},flags,stacktype{{0x00}});
        test(script,stacktype{{0x00}, {0x01}},flags,stacktype{{0x01}});
        test(script,stacktype{{0x01}, {0x00}},flags,stacktype{{0x01}});
        test(script,stacktype{{0x01}, {0x01}},flags,stacktype{{0x01}});

        test(script,stacktype{{0x00, 0x00}, {0x00, 0x00}},flags,stacktype{{0x00, 0x00}});
        test(script,stacktype{{0x00, 0x00}, {0x01, 0x00}},flags,stacktype{{0x01, 0x00}});
        test(script,stacktype{{0x01, 0x00}, {0x00, 0x00}},flags,stacktype{{0x01, 0x00}});
        test(script,stacktype{{0x01, 0x00}, {0x01, 0x00}},flags,stacktype{{0x01, 0x00}});

        {
        valtype maxlenbin1(MAX_SCRIPT_ELEMENT_SIZE, 0x01);
        valtype maxlenbin2(MAX_SCRIPT_ELEMENT_SIZE, 0xF0);
        valtype maxlenbin3(MAX_SCRIPT_ELEMENT_SIZE, 0x01 | 0xF0);
        test(script,stacktype{maxlenbin1,maxlenbin2},flags,stacktype{maxlenbin3});
        }

        {
        valtype maxlenbin1(MAX_SCRIPT_ELEMENT_SIZE, 0x3C);
        valtype maxlenbin2(MAX_SCRIPT_ELEMENT_SIZE, 0xDB);
        valtype maxlenbin3(MAX_SCRIPT_ELEMENT_SIZE, 0x3C | 0xDB);
        test(script,stacktype{maxlenbin1,maxlenbin2},flags,stacktype{maxlenbin3});
        }

    }

    /// OP_XOR tests

    void test_xor(uint32_t flags) {
        CScript script;
        script << OP_XOR;
        test_bitwiseop(script,flags);

        test(script,stacktype{{0x00}, {0x00}},flags,stacktype{{0x00}});
        test(script,stacktype{{0x00}, {0x01}},flags,stacktype{{0x01}});
        test(script,stacktype{{0x01}, {0x00}},flags,stacktype{{0x01}});
        test(script,stacktype{{0x01}, {0x01}},flags,stacktype{{0x00}});

        test(script,stacktype{{0x00, 0x00}, {0x00, 0x00}},flags,stacktype{{0x00, 0x00}});
        test(script,stacktype{{0x00, 0x00}, {0x01, 0x00}},flags,stacktype{{0x01, 0x00}});
        test(script,stacktype{{0x01, 0x00}, {0x00, 0x00}},flags,stacktype{{0x01, 0x00}});
        test(script,stacktype{{0x01, 0x00}, {0x01, 0x00}},flags,stacktype{{0x00, 0x00}});

        {
        valtype maxlenbin1(MAX_SCRIPT_ELEMENT_SIZE, 0x01);
        valtype maxlenbin2(MAX_SCRIPT_ELEMENT_SIZE, 0xF0);
        valtype maxlenbin3(MAX_SCRIPT_ELEMENT_SIZE, 0x01 ^ 0xF0);
        test(script,stacktype{maxlenbin1,maxlenbin2},flags,stacktype{maxlenbin3});
        }

        {
        valtype maxlenbin1(MAX_SCRIPT_ELEMENT_SIZE, 0x3C);
        valtype maxlenbin2(MAX_SCRIPT_ELEMENT_SIZE, 0xDB);
        valtype maxlenbin3(MAX_SCRIPT_ELEMENT_SIZE, 0x3C ^ 0xDB);
        test(script,stacktype{maxlenbin1,maxlenbin2},flags,stacktype{maxlenbin3});
        }
    }

    /// OP_DIV tests

    void test_div(uint32_t flags) {
        CScript script;
        script << OP_DIV;

        test(script,stacktype(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
        test(script,stacktype{{}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);

        //test not valid numbers
        test(script,stacktype{{0x01, 0x02, 0x03, 0x04, 0x05}, {0x01, 0x02, 0x03, 0x04, 0x05}},flags,SCRIPT_ERR_UNKNOWN_ERROR);
        test(script,stacktype{{0x01, 0x02, 0x03, 0x04, 0x05}, {0x01}},flags,SCRIPT_ERR_UNKNOWN_ERROR);
        test(script,stacktype{{0x01, 0x05}, {0x01, 0x02, 0x03, 0x04, 0x05}},flags,SCRIPT_ERR_UNKNOWN_ERROR);
        //b == 0 ; b is equal to any type of zero
        test(script,stacktype{{0x01, 0x05}, {}},flags,SCRIPT_ERR_DIV_BY_ZERO);
        test(script,stacktype{{}, {}},flags,SCRIPT_ERR_DIV_BY_ZERO);
        if (flags&SCRIPT_VERIFY_MINIMALDATA) {
            test(script,stacktype{{}, {0x00}},flags,SCRIPT_ERR_UNKNOWN_ERROR); //not minimal encoding
            test(script,stacktype{{}, {0x00, 0x00}},flags,SCRIPT_ERR_UNKNOWN_ERROR);
        }
        else {
            test(script,stacktype{{}, {0x00}},flags,SCRIPT_ERR_DIV_BY_ZERO); 
            test(script,stacktype{{}, {0x00, 0x00}},flags,SCRIPT_ERR_DIV_BY_ZERO);
        }       
        //185377af/85f41b01 =-4
        //185377af/00001b01 =E69D
        test(script,stacktype{{0xaf, 0x77, 0x53, 0x18}, {0x01, 0x1b, 0xf4, 0x85}},flags,stacktype{{0x84}});
        test(script,stacktype{{0xaf, 0x77, 0x53, 0x18}, {0x01, 0x1b}},flags,stacktype{{0x9D, 0xE6, 0x00}});
        //15/4 =3
        //15/-4 =-3
        //-15/4 =-3
        //-15/-4 =3
        test(script,stacktype{{0x0f}, {0x04}},flags,stacktype{{0x03}});
        test(script,stacktype{{0x0f}, {0x84}},flags,stacktype{{0x83}});
        test(script,stacktype{{0x8f}, {0x04}},flags,stacktype{{0x83}});
        test(script,stacktype{{0x8f}, {0x84}},flags,stacktype{{0x03}});
        //15000/4 =3750
        //15000/-4 =-3750
        //-15000/4 =-3750
        //-15000/-4 =3750
        test(script,stacktype{{0x98, 0x3a}, {0x04}},flags,stacktype{{0xa6, 0x0e}});
        test(script,stacktype{{0x98, 0x3a}, {0x84}},flags,stacktype{{0xa6, 0x8e}});
        test(script,stacktype{{0x98, 0xba}, {0x04}},flags,stacktype{{0xa6, 0x8e}});
        test(script,stacktype{{0x98, 0xba}, {0x84}},flags,stacktype{{0xa6, 0x0e}});
        //15000/4000 =3
        //15000/-4000 =-3
        //-15000/4000 =-3
        //-15000/-4000 =3
        test(script,stacktype{{0x98, 0x3a}, {0xa0, 0x0f}},flags,stacktype{{0x03}});
        test(script,stacktype{{0x98, 0x3a}, {0xa0, 0x8f}},flags,stacktype{{0x83}});
        test(script,stacktype{{0x98, 0xba}, {0xa0, 0x0f}},flags,stacktype{{0x83}});
        test(script,stacktype{{0x98, 0xba}, {0xa0, 0x8f}},flags,stacktype{{0x03}});
        //15000000/4000 =3750
        //15000000/-4000 =-3750
        //-15000000/4000 =-3750
        //-15000000/-4000 =3750
        test(script,stacktype{{0xc0, 0xe1, 0xe4, 0x00}, {0xa0, 0x0f}},flags,stacktype{{0xa6, 0x0e}});
        test(script,stacktype{{0xc0, 0xe1, 0xe4, 0x00}, {0xa0, 0x8f}},flags,stacktype{{0xa6, 0x8e}});
        test(script,stacktype{{0xc0, 0xe1, 0xe4, 0x80}, {0xa0, 0x0f}},flags,stacktype{{0xa6, 0x8e}});
        test(script,stacktype{{0xc0, 0xe1, 0xe4, 0x80}, {0xa0, 0x8f}},flags,stacktype{{0xa6, 0x0e}});
        //15000000/4 =3750000
        //15000000/-4 =-3750000
        //-15000000/4 =-3750000
        //-15000000/-4 =3750000
        test(script,stacktype{{0xc0, 0xe1, 0xe4, 0x00}, {0x04}},flags,stacktype{{0x70, 0x38, 0x39}});
        test(script,stacktype{{0xc0, 0xe1, 0xe4, 0x00}, {0x84}},flags,stacktype{{0x70, 0x38, 0xb9}});
        test(script,stacktype{{0xc0, 0xe1, 0xe4, 0x80}, {0x04}},flags,stacktype{{0x70, 0x38, 0xb9}});
        test(script,stacktype{{0xc0, 0xe1, 0xe4, 0x80}, {0x84}},flags,stacktype{{0x70, 0x38, 0x39}});
    }

    /// OP_MOD tests

    void test_mod(uint32_t flags) {
        CScript script;
        script << OP_MOD;

        test(script,stacktype(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
        test(script,stacktype{{}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);

        //test not valid numbers
        test(script,stacktype{{0x01, 0x02, 0x03, 0x04, 0x05}, {0x01, 0x02, 0x03, 0x04, 0x05}},flags,SCRIPT_ERR_UNKNOWN_ERROR);
        test(script,stacktype{{0x01, 0x02, 0x03, 0x04, 0x05}, {0x01}},flags,SCRIPT_ERR_UNKNOWN_ERROR);
        test(script,stacktype{{0x01, 0x05}, {0x01, 0x02, 0x03, 0x04, 0x05}},flags,SCRIPT_ERR_UNKNOWN_ERROR);

        //mod by 0
        test(script,stacktype{{0x01, 0x05}, {}},flags,SCRIPT_ERR_MOD_BY_ZERO);

        //56488123%321 =148
        //56488123%3 =1
        //56488123%564881230 =56488123
        test(script,stacktype{{0xbb, 0xf0, 0x5d, 0x03}, {0x41, 0x01}},flags,stacktype{{0x94, 0x00}});
        test(script,stacktype{{0xbb, 0xf0, 0x5d, 0x03}, {0x03}},flags,stacktype{{0x01}});
        test(script,stacktype{{0xbb, 0xf0, 0x5d, 0x03}, {0x4e, 0x67, 0xab, 0x21}},flags,stacktype{{0xbb, 0xf0, 0x5d, 0x03}});

        //-56488123%321 = -148
        //-56488123%3 = -1
        //-56488123%564881230 = -56488123
        test(script,stacktype{{0xbb, 0xf0, 0x5d, 0x83}, {0x41, 0x01}},flags,stacktype{{0x94, 0x80}});
        test(script,stacktype{{0xbb, 0xf0, 0x5d, 0x83}, {0x03}},flags,stacktype{{0x81}});
        test(script,stacktype{{0xbb, 0xf0, 0x5d, 0x83}, {0x4e, 0x67, 0xab, 0x21}},flags,stacktype{{0xbb, 0xf0, 0x5d, 0x83}});
    }

    /// OP_CAT

    void test_cat() {
        CScript script;
        script << OP_CAT;

        // Two inputs required
        CheckOpError(stacktype(), script, SCRIPT_ERR_INVALID_STACK_OPERATION);
        CheckOpError(stacktype{{0x00}}, script, SCRIPT_ERR_INVALID_STACK_OPERATION);

        valtype maxlength_valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x00);

        // Concatenation producing illegal sized output
        CheckOpError(stacktype{{maxlength_valtype}, {0x00}}, script, SCRIPT_ERR_PUSH_SIZE);
    
        // Concatenation of a max-sized valtype with empty is legal
        CheckOp(stacktype{{maxlength_valtype}, {}}, script, maxlength_valtype);
        CheckOp(stacktype{{}, {maxlength_valtype}}, script, maxlength_valtype);

        // Concatenation of a zero length operand
        CheckOp(stacktype{{0x01}, {}}, script, valtype{0x01});
        CheckOp(stacktype{{}, {0x01}}, script, valtype{0x01});

        // Concatenation of two empty operands results in empty valtype
        CheckOp(stacktype{{}, {}}, script, valtype{});

        // Concatenating two operands generates the correct result
        CheckOp(stacktype{{0x00}, {0x00}}, script, {0x00, 0x00});
        CheckOp(stacktype{{0x01}, {0x02}}, script, {0x01, 0x02});
        CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
                          {0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}},
             script,
             valtype{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 
                     0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14});
    }

    /// OP_SPLIT

    void test_split() {
        CScript script;
        script << OP_SPLIT; //inputs: x n; outputs: x1 x2

        // Two inputs required
        CheckOpError(stacktype{}, script, SCRIPT_ERR_INVALID_STACK_OPERATION);
        CheckOpError(stacktype{{0x01}}, script, SCRIPT_ERR_INVALID_STACK_OPERATION);

        // Length of 2nd input greater than CScriptNum::nDefaultMaxNumSize
        valtype illegal_numeric_valtype(CScriptNum::nDefaultMaxNumSize, 0x01);
        illegal_numeric_valtype.push_back(0x00);
        CheckOpError(stacktype{{0x01}, illegal_numeric_valtype}, script, SCRIPT_ERR_UNKNOWN_ERROR);

        // if n == 0, then x1 is the empty array and x2 == x;
        //execution of OP_SPLIT on empty array results in two empty arrays.
        CheckOp(stacktype{{}, {}}, script, stacktype{{}, {}});
        CheckOp(stacktype{{0x01}, {}}, script, stacktype{{}, {0x01}}); //x 0 OP_SPLIT -> OP_0 x
        CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {}}, script, stacktype{{}, {0x01, 0x02, 0x03, 0x04}});

        // if n == len(x) then x1 == x and x2 is the empty array
        CheckOp(stacktype{{0x01}, {0x01}}, script, stacktype{{0x01}, {}}); 
        CheckOp(stacktype{{0x01, 0x02, 0x03}, {0x03}}, script, stacktype{{0x01, 0x02, 0x03}, {}}); //x len(x) OP_SPLIT -> x OP_0

        // if n > len(x), then the operator must fail; x (len(x) + 1) OP_SPLIT -> FAIL
        CheckOpError(stacktype{{}, {0x01}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);
        CheckOpError(stacktype{{0x01}, {0x02}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);
        CheckOpError(stacktype{{0x01, 0x02, 0x03}, {0x04}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);
        CheckOpError(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x05}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);

        // if n < 0 the operator must fail.
        CheckOpError(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x81}}, script, SCRIPT_ERR_INVALID_SPLIT_RANGE);

        CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x01}}, script, stacktype{{0x01}, {0x02, 0x03, 0x04}});
        CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x02}}, script, stacktype{{0x01, 0x02}, {0x03, 0x04}});
        CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x03}}, script, stacktype{{0x01, 0x02, 0x03}, {0x04}});
        CheckOp(stacktype{{0x01, 0x02, 0x03, 0x04}, {0x04}}, script, stacktype{{0x01, 0x02, 0x03, 0x04}, {}});

        //split of a max-len valtype
        valtype maxlength_valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x00);
        CheckOp(stacktype{maxlength_valtype, {}}, script, stacktype{{}, maxlength_valtype});
    }

    /// OP_CAT + OP_SPLIT

    void test_cat_split(const valtype& x) {
        CScript script;

        // x n OP_SPLIT OP_CAT -> x - for all x and for all 0 <= n <= len(x)
        script << OP_SPLIT << OP_CAT;
        CheckOp(stacktype{x, {}}, script, x);
        for (uint8_t i=1; i <= x.size(); ++i) {
            CheckOp(stacktype{x, {i}}, script, x);
        }
    }

    void test_cat_split() {
        test_cat_split({});
        test_cat_split({0x01});
        test_cat_split({0x01, 0x02});
        test_cat_split({0x01, 0x02, 0x03});
    }

    /// OP_BIN2NUM tests
   
    /// mk_bin - helper function
    ///    input:
    ///        a (native) number - maybe LE or BE format.
    ///    output: 
    ///        Bitcoin representation (up to 256 bytes, big-endian, 0x80 in 
    ///        first byte used for sign) - removes the sign, constructs a BE 
    ///        array of bytes with the positive number, the adds the sign.
    ///
    valtype mk_bin(int64_t v0) {
        if (v0 == 0)
            return valtype{0x00};
        bool neg = v0 < 0;
        uint64_t v = htobe64(neg ? -v0 : v0); 
        valtype ans;
        ans.reserve(8);
        uint8_t* p = reinterpret_cast<uint8_t*>(&v);
        for (size_t i = 0; i < 8; ++i, ++p) {
            if (ans.empty()) {
                if (!*p) continue;
                if (*p & 0x80) ans.push_back(0x00); // first bit looks like a sign but it is not, add a leading 0
            }
            ans.push_back(*p);
        }
        if (neg) 
            *ans.begin() |= 0x80; //add the sign
        return move(ans);
    }

    void test_bin2num_opcode() {
        CScript script;
        script << OP_BIN2NUM;

        // Test the mk_bin function
        { valtype i{0x00, 0x80, 0x00, 0x05}; BOOST_CHECK_EQUAL(mk_bin(0x800005) == i, true); }
        { valtype i{0x05}; BOOST_CHECK_EQUAL(mk_bin(0x000005) == i, true); }
        { valtype i{0x01, 0x05}; BOOST_CHECK_EQUAL(mk_bin(0x000105) == i, true); }
        { valtype i{0x81, 0x05}; BOOST_CHECK_EQUAL(mk_bin(-0x000105) == i, true); }

        CheckOpError(stacktype(), script, SCRIPT_ERR_INVALID_STACK_OPERATION);
        CheckOp(mk_bin(0), script, valtype{});

        CheckOp(mk_bin(std::numeric_limits<int32_t>::max() >> 1), script, 
                CScriptNum(std::numeric_limits<int32_t>::max() >> 1).getvch());

        CheckOp(mk_bin(std::numeric_limits<int32_t>::min() >> 1), script, 
                CScriptNum(std::numeric_limits<int32_t>::min() >> 1).getvch());

        CheckOpError(mk_bin((std::numeric_limits<int32_t>::max() >> 1) + 1), script, 
                SCRIPT_ERR_INVALID_BIN2NUM_OPERATION);

        CheckOpError(mk_bin((std::numeric_limits<int32_t>::min() >> 1) - 1), script, 
                SCRIPT_ERR_INVALID_BIN2NUM_OPERATION);

        CheckOp(mk_bin(106894), script, CScriptNum(106894).getvch());
        CheckOp(mk_bin(-106894), script, CScriptNum(-106894).getvch());
        CheckOp(mk_bin(0), script, CScriptNum(0).getvch());
    }

    /// OP_NUM2BIN tests

    /// make expected value - helper function
    ///    input: 
    ///        number in LE byte order, desired output byte length
    ///    output: 
    ///        Bitcoin representatio - removes the sign, constructs a BE array
    ////       of bytes with the positive number, then it adds the sign.
    ///    
    valtype make_ev(valtype v, size_t sz) { //v contains a num in LE
        if (v.empty()) 
            return vector<uint8_t>(sz, 0);
        valtype  ans;
        assert(sz >= v.size());
        ans.reserve(sz);
        bool neg = *v.rbegin() & 0x80;
        *v.rbegin() &= ~0x80;
        size_t pad = sz - v.size();
        for (uint8_t i = 0; i < pad; ++i) {
            ans.push_back(0);
        }
        for (auto i = v.rbegin(); i != v.rend(); ++i) {
            ans.push_back(*i);
        }
        if (neg) 
            *ans.begin() |= 0x80;
        return ans;
    }
    
    void test_num2bin(const CScript& script, valtype v) {
        if (v.empty()) 
            return;
        for (uint8_t i = 0; i < v.size(); ++i) {
            if (i == 0)
                CheckOpError(stacktype{v, {}}, script, 
                             SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); 
            else
                CheckOpError(stacktype{v, {i}}, script, 
                             SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); 
        }
        for (uint8_t i = v.size(); i <= CScriptNum::nDefaultMaxNumSize; ++i) {
            if (i == 0)
                CheckOp(stacktype{v, {}}, script, make_ev(v,i)); 
            else
                CheckOp(stacktype{v, {i}}, script, make_ev(v,i)); 
        }
    }

    void test_num2bin_opcode() {
        CScript script;
        script << OP_NUM2BIN;

        CheckOpError(stacktype(), script, SCRIPT_ERR_INVALID_STACK_OPERATION);
        CheckOpError(stacktype{{4}}, script, SCRIPT_ERR_INVALID_STACK_OPERATION);

        CheckOpError(stacktype{{0x02}, {CScriptNum::nDefaultMaxNumSize + 1}}, 
                     script, SCRIPT_ERR_INVALID_NUM2BIN_OPERATION);

        CheckOpError(stacktype{{0x85}, {CScriptNum::nDefaultMaxNumSize + 1}}, 
                     script, SCRIPT_ERR_INVALID_NUM2BIN_OPERATION);

        CheckOpError(stacktype{{0x02}, {}}, script, 
                     SCRIPT_ERR_INVALID_NUM2BIN_OPERATION);

        CheckOpError(stacktype{{0x85}, {0x85}}, script, 
                     SCRIPT_ERR_INVALID_NUM2BIN_OPERATION);

        CheckOpError(stacktype{{0x85}, {}}, script, 
                     SCRIPT_ERR_INVALID_NUM2BIN_OPERATION);

        test_num2bin(script, {});
        test_num2bin(script, {0x7f});
        test_num2bin(script, {0xff, 0x7f}); //LE for 0x7FFF
        test_num2bin(script, {0x02, 0x71});
        test_num2bin(script, {0xff, 0xff, 0x7f});
        test_num2bin(script, {0x03, 0x02, 0x71});
        test_num2bin(script, {0xff, 0xff, 0xff, 0x7f});
        test_num2bin(script, {0x04, 0x03, 0x02, 0x71});
        test_num2bin(script, {0x81});
        test_num2bin(script, {0xff, 0x80});
        test_num2bin(script, {0xaf, 0x81});
        test_num2bin(script, {0xed, 0x60, 0x83});
        test_num2bin(script, {0xb6, 0xe3, 0x81});
        test_num2bin(script, {0x81, 0x9a, 0x6e, 0x84});
        test_num2bin(script, {0xe4, 0xc3, 0x92, 0x91});
    }

    /// OP_BIN2NUM + OP_NUM2BIN tests

    void test_bin2num_num2bin(const CScript& script, int sz, int64_t v) {
        auto x = mk_bin(v);
        CheckOp(stacktype{x}, script, make_ev(CScriptNum(v).getvch(), sz));
    }

    void test_num2bin_bin2num(const CScript& script, int64_t v) {
        CheckOp(stacktype{CScriptNum(v).getvch()}, script, CScriptNum(v).getvch());
    }

    void test_bin2num_num2bin(int sz) {
        CScript script;
        script << OP_BIN2NUM << sz << OP_NUM2BIN;
        test_bin2num_num2bin(script, sz, 0);
        test_bin2num_num2bin(script, sz, 1);
        test_bin2num_num2bin(script, sz, -1);
        if (sz >= 2) {
            test_bin2num_num2bin(script,sz, 321);
            test_bin2num_num2bin(script,sz, -321);
            if (sz >= 3) {
                test_bin2num_num2bin(script, sz, 106894);
                test_bin2num_num2bin(script, sz, -106894);
                if (sz >= 4) {
                    test_bin2num_num2bin(script, sz, std::numeric_limits<int32_t>::max() >> 1);
                    test_bin2num_num2bin(script, sz, std::numeric_limits<int32_t>::min() >> 1);
                }
            }
        }
    }

    void test_num2bin_bin2num(int sz) {
        CScript script;
        script << sz << OP_NUM2BIN << OP_BIN2NUM;
        test_num2bin_bin2num(script, 0);
        test_num2bin_bin2num(script, 1);
        test_num2bin_bin2num(script, -1);
        if (sz >= 2) {
            test_num2bin_bin2num(script, 321);
            test_num2bin_bin2num(script, -321);
            if (sz >= 3) {
                test_num2bin_bin2num(script, 106894);
                test_num2bin_bin2num(script, -106894);
                if (sz >= 4) {
                    test_num2bin_bin2num(script, std::numeric_limits<int32_t>::max() >> 1);
                    test_num2bin_bin2num(script, std::numeric_limits<int32_t>::min() >> 1);
                }
            }
        }
    }

    void test_bin2num_num2bin() {
        test_bin2num_num2bin(4); //expect 4 byte output
        test_bin2num_num2bin(3); //expect 3 byte output
        test_bin2num_num2bin(2); //expect 2 byte output
        test_bin2num_num2bin(1); //expect 1 byte output
    }

    void test_num2bin_bin2num() {
        test_num2bin_bin2num(4); //4 byte num2bin output
        test_num2bin_bin2num(3); //3 byte num2bin output
        test_num2bin_bin2num(2); //2 byte num2bin output
        test_num2bin_bin2num(1); //1 byte num2bin output
    }

}

/// Entry points

BOOST_AUTO_TEST_SUITE(op_code)

BOOST_AUTO_TEST_CASE(op_and) {
    test_and(0);
    test_and(STANDARD_SCRIPT_VERIFY_FLAGS);
    test_and(STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
    test_and(STANDARD_LOCKTIME_VERIFY_FLAGS);
}

BOOST_AUTO_TEST_CASE(op_or) {
    test_or(0);
    test_or(STANDARD_SCRIPT_VERIFY_FLAGS);
    test_or(STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
    test_or(STANDARD_LOCKTIME_VERIFY_FLAGS);
}

BOOST_AUTO_TEST_CASE(op_xor) {
    test_xor(0);
    test_xor(STANDARD_SCRIPT_VERIFY_FLAGS);
    test_xor(STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
    test_xor(STANDARD_LOCKTIME_VERIFY_FLAGS);
}

BOOST_AUTO_TEST_CASE(op_div) {
    test_div(0);
    test_div(STANDARD_SCRIPT_VERIFY_FLAGS);
    test_div(STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
    test_div(STANDARD_LOCKTIME_VERIFY_FLAGS);
}

BOOST_AUTO_TEST_CASE(op_mod) {
    test_mod(0);
    test_mod(STANDARD_SCRIPT_VERIFY_FLAGS);
    test_mod(STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
    test_mod(STANDARD_LOCKTIME_VERIFY_FLAGS);
}

BOOST_AUTO_TEST_CASE(op_cat) {
    test_cat();
}

BOOST_AUTO_TEST_CASE(op_split) {
    test_split();
}

BOOST_AUTO_TEST_CASE(cat_split) {
    test_cat_split();
}

BOOST_AUTO_TEST_CASE(bin2num_opcode_tests) {
   test_bin2num_opcode();
}

BOOST_AUTO_TEST_CASE(num2bin_opcode_tests) {
    test_num2bin_opcode();
}

BOOST_AUTO_TEST_CASE(bin2num_num2bin_testsG) {
    test_bin2num_num2bin();
}

BOOST_AUTO_TEST_CASE(num2bin_bin2num) {
    test_num2bin_bin2num();
}

BOOST_AUTO_TEST_SUITE_END()

