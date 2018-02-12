// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "data/script_tests.json.h"

#include "script/script.h"
#include "script/interpreter.h"
#include "policy/policy.h"
#include <boost/test/unit_test.hpp>

using namespace std;

namespace {
	typedef vector<uint8_t> item;
	typedef vector<item> stack_t;

	void test(const CScript& script, stack_t stack, uint32_t flags, ScriptError e) {
		ScriptError err;
		BaseSignatureChecker sigchecker;
		bool r=EvalScript(stack, script, flags, sigchecker, &err);
		BOOST_CHECK_EQUAL( r, false );
		BOOST_CHECK_EQUAL( err, SCRIPT_ERR_INVALID_STACK_OPERATION );
	}
	void test(const CScript& script, stack_t stack, uint32_t flags, stack_t expected) {
		ScriptError err;
		BaseSignatureChecker sigchecker;
		bool r=EvalScript(stack, script, flags, sigchecker, &err);
		BOOST_CHECK_EQUAL(r, true);
		BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
		BOOST_CHECK_EQUAL(stack==expected, true);
	}

	vector<uint8_t> make_ev(vector<uint8_t> v, size_t sz) {
		vector<uint8_t> ans;
		if (v.empty()) return ans;
		if (sz<v.size()) {
			return ans;
		}
		ans.reserve(sz);
		bool neg=v[0]&0x80;
		v[0]&=~0x80;
		size_t pad=sz-v.size();
		for (uint8_t i=0; i<pad; ++i) {
			ans.push_back(0);
		}
		for (auto& i:v) {
			ans.push_back(i);
		}
		if (neg) *ans.begin()|=0x80;
		return ans;
	}

	void test(const CScript& script, vector<uint8_t> v, uint32_t flags) {
		if (v.empty()) return;
		if (v.size()>sizeof(uint8_t)) return;
		for (uint8_t i=v.size(); i<MAX_NUM2BIN_SIZE; ++i) {
			test(script,stack_t{v,{i}},flags,stack_t{make_ev(v,i)}); //2 item stack, negative, size 1
		}
	}


	void test(const CScript& script, uint32_t flags) {
		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION); //empty stack
		test(script,stack_t{{4}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION); //1 item stack
		test(script,stack_t{{0x02},{MAX_NUM2BIN_SIZE+1}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, positive, size>MAX_NUM2BIN_SIZE
		test(script,stack_t{{0x85},{MAX_NUM2BIN_SIZE+1}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, negative, size>MAX_NUM2BIN_SIZE
		test(script,stack_t{{0x02},{0x85}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, positive, size <0
		test(script,stack_t{{0x02},{0}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, positive, size 0
		test(script,stack_t{{0x85},{0x85}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, negative, size <0
		test(script,stack_t{{0x85},{0}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, negative, size 0
		test(script,{0x7f},flags);
		test(script,{0x7f,0xff},flags);
		test(script,{0x71,0x02},flags);
		test(script,{0x7f,0xff,0xff},flags);
		test(script,{0x71,0x02,0x03},flags);
		test(script,{0x7f,0xff,0xff,0xff},flags);
		test(script,{0x71,0x02,0x03,0x04},flags);
		test(script,{0x81},flags);
		test(script,{0x80,0x01},flags);
		test(script,{0x81,0x02},flags);
		test(script,{0x80,0x00,0x01},flags);
		test(script,{0x81,0x02,0x03},flags);
		test(script,{0x80,0x00,0x00,0x01},flags);
		test(script,{0x81,0x02,0x03,0x04},flags);
	}
}




//BOOST_FIXTURE_TEST_SUITE(op_code, op_code_test)
BOOST_AUTO_TEST_SUITE(op_code)


BOOST_AUTO_TEST_CASE(op_num2bin) {
	CScript script;
	script << OP_NUM2BIN;
	test(script, 0);
	test(script, STANDARD_SCRIPT_VERIFY_FLAGS);
	test(script, STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
	test(script, STANDARD_LOCKTIME_VERIFY_FLAGS);
}


BOOST_AUTO_TEST_SUITE_END()



