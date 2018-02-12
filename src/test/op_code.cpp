// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "data/script_tests.json.h"

#include "script/script.h"
#include "script/interpreter.h"
#include <boost/test/unit_test.hpp>

using namespace std;

struct op_code_test {

};

typedef vector<uint8_t> item;
typedef vector<item> stack_t;

//BOOST_FIXTURE_TEST_SUITE(op_code, op_code_test)
BOOST_AUTO_TEST_SUITE(op_code)

BOOST_AUTO_TEST_CASE(op_num2bin) {
	CScript script;
	script << OP_NUM2BIN;

	BaseSignatureChecker sigchecker;
	
	{ //empty stack
	stack_t stack;
	ScriptError err;
	uint32_t flags=0;
	bool r=EvalScript(stack, script, flags, sigchecker, &err);
	BOOST_CHECK_EQUAL( r, false );
	}
	{ //1 item stack
	stack_t stack;
	stack.push_back(item{4});
	ScriptError err;
	uint32_t flags=0;
	bool r=EvalScript(stack, script, flags, sigchecker, &err);
	BOOST_CHECK_EQUAL( r, false );
	}
	{ //2 item stack, positive
	stack_t stack;
	stack.push_back(item{0x02});
	stack.push_back(item{4});
	ScriptError err;
	uint32_t flags=0;
	bool r=EvalScript(stack, script, flags, sigchecker, &err);
	BOOST_CHECK_EQUAL( r, true );
	BOOST_CHECK_EQUAL( stack.size(), 1 );
	BOOST_CHECK_EQUAL( stack[0].size(), 4 );
	BOOST_CHECK_EQUAL( stack[0][0], 0 );
	BOOST_CHECK_EQUAL( stack[0][1], 0 );
	BOOST_CHECK_EQUAL( stack[0][2], 0 );
	BOOST_CHECK_EQUAL( stack[0][3], 2 );
	}
	{ //2 item stack, negative
	stack_t stack;
	stack.push_back(item{0x85});
	stack.push_back(item{4});
	ScriptError err;
	uint32_t flags=0;
	bool r=EvalScript(stack, script, flags, sigchecker, &err);
	BOOST_CHECK_EQUAL( r, true );
	BOOST_CHECK_EQUAL( stack.size(), 1 );
	BOOST_CHECK_EQUAL( stack[0].size(), 4 );
	BOOST_CHECK_EQUAL( stack[0][0], 0x80 );
	BOOST_CHECK_EQUAL( stack[0][1], 0 );
	BOOST_CHECK_EQUAL( stack[0][2], 0 );
	BOOST_CHECK_EQUAL( stack[0][3], 5 );
	}

}


BOOST_AUTO_TEST_SUITE_END()
