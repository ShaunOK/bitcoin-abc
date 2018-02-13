// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "data/script_tests.json.h"

#include "script/script.h"
#include "script/interpreter.h"
#include "policy/policy.h"
#include "core_io.h"
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <iomanip>

using namespace std;

namespace {
	typedef vector<uint8_t> item;
	typedef vector<item> stack_t;

	void print(const item& i) {
		for (auto& s:i)	cout << hex << setw(2) << setfill('0') << (int) s << " ";
		cout << endl;
	}

	void print(const stack_t& i) {
		for (auto& s:i) print(s);
		cout << endl;
	}

	void test(const CScript& script, stack_t stack, uint32_t flags, ScriptError e) {
		ScriptError err;
		BaseSignatureChecker sigchecker;
		bool r=EvalScript(stack, script, flags, sigchecker, &err);
		BOOST_CHECK_EQUAL(r, false);
		BOOST_CHECK_EQUAL(err, e);
	}
	void test(const CScript& script, stack_t stack, uint32_t flags, stack_t expected) {
cout << "--------------" << endl;
cout << "Checking script \"" << FormatScript(script) << "\" flags " << flags << endl;
cout << "with input stack: " << endl;
print(stack);
cout << "expected output stack: " << endl;
print(expected);

		ScriptError err;
		BaseSignatureChecker sigchecker;
		bool r=EvalScript(stack, script, flags, sigchecker, &err);
cout << "got output stack: " << endl;
print(stack);

		BOOST_CHECK_EQUAL(r, true);
		BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
		BOOST_CHECK_EQUAL(stack==expected, true);
cout << "--------------" << endl;
	}

	vector<uint8_t> make_ev(vector<uint8_t> v, size_t sz) { //v contains a num in LE
		vector<uint8_t> ans;
		if (v.empty()) return ans;
		if (sz<v.size()) {
			return ans;
		}
		ans.reserve(sz);
		bool neg=*v.rbegin()&0x80;
		*v.rbegin()&=~0x80;
		size_t pad=sz-v.size();
		for (uint8_t i=0; i<pad; ++i) {
			ans.push_back(0);
		}
		for (auto i=v.rbegin(); i!=v.rend(); ++i) {
			ans.push_back(*i);
		}
		if (neg) *ans.begin()|=0x80;
		return ans;
	}

	void test_num2bin(const CScript& script, vector<uint8_t> v, uint32_t flags) {
		if (v.empty()) return;
		for (uint8_t i=0; i<v.size(); ++i) {
			test(script,stack_t{v,{i}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); 
		}
		for (uint8_t i=v.size(); i<=MAX_NUM2BIN_SIZE; ++i) {
			test(script,stack_t{v,{i}},flags,stack_t{make_ev(v,i)}); 
		}
	}


	void test_num2bin(uint32_t flags) {
		CScript script;
		script << OP_NUM2BIN;
		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION); //empty stack
		test(script,stack_t{{4}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION); //1 item stack
		test(script,stack_t{{0x02},{MAX_NUM2BIN_SIZE+1}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, positive, size>MAX_NUM2BIN_SIZE
		test(script,stack_t{{0x85},{MAX_NUM2BIN_SIZE+1}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, negative, size>MAX_NUM2BIN_SIZE
		test(script,stack_t{{0x02},{0x85}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, positive, size <0
		test(script,stack_t{{0x02},{0}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, positive, size 0
		test(script,stack_t{{0x85},{0x85}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, negative, size <0
		test(script,stack_t{{0x85},{0}},flags,SCRIPT_ERR_INVALID_NUM2BIN_OPERATION); //2 item stack, negative, size 0
		test_num2bin(script,{0x7f},flags);
		test_num2bin(script,{0xff,0x7f},flags); //LE for 0x7FFF
		test_num2bin(script,{0x02,0x71},flags);
		test_num2bin(script,{0xff,0xff,0x7f},flags);
		test_num2bin(script,{0x03,0x02,0x71},flags);
		test_num2bin(script,{0xff,0xff,0xff,0x7f},flags);
		test_num2bin(script,{0x04,0x03,0x02,0x71},flags);
		test_num2bin(script,{0x81},flags);
		test_num2bin(script,{0x01,0x80},flags);
		test_num2bin(script,{0x02,0x81},flags);
		test_num2bin(script,{0x01,0x00,0x80},flags);
		test_num2bin(script,{0x03,0x02,0x81},flags);
		test_num2bin(script,{0x01,0x00,0x00,0x80},flags);
		test_num2bin(script,{0x04,0x03,0x02,0x81},flags);
	}


	item mk_bin(int64_t v0) {
		cout << endl << "mk_bin:" << endl;
		if (v0==0) return item{0x00};
		cout << "item:" << hex << v0 << endl;
		uint64_t v=htole64(v0); 
		{
		uint8_t* p=reinterpret_cast<uint8_t*>(&v);
		cout << "item LE:" << hex;
		cout << ' ' << (int)*p; ++p;
		cout << ' ' << (int)*p; ++p;
		cout << ' ' << (int)*p; ++p;
		cout << ' ' << (int)*p; ++p;
		cout << ' ' << (int)*p; ++p;
		cout << ' ' << (int)*p; ++p;
		cout << ' ' << (int)*p; ++p;
		cout << ' ' << (int)*p << endl;
		}
		item ans;
		ans.reserve(sizeof(uint64_t));

		uint8_t* pp=reinterpret_cast<uint8_t*>(&v)+sizeof(int64_t)-1;
		while(*pp==0) --pp;
		
		
		bool neg=*pp&0x80;
cout << "neg: " << neg << endl;
		*pp&=~0x80; //remove sign of the MSbyte
		for (size_t i=0; i<sizeof(uint64_t); ++i) {
			uint8_t* p=reinterpret_cast<uint8_t*>(&v)+(sizeof(uint64_t)-1-i);
			if (ans.empty() && !*p) continue;
			if (neg && ans.empty() && *p&0x80) ans.push_back(0x00);
			ans.push_back(*p);
		}
		if (neg) *ans.begin()|=0x80;
		cout << "ans:" << endl;
		print(ans);

		return move(ans);
	}

	void test_bin2num(uint32_t flags) {
		CScript script;
		script << OP_BIN2NUM;

		{ item i{0x85}; BOOST_CHECK_EQUAL(mk_bin(0x800005)==i, true); }
		{ item i{0x05}; BOOST_CHECK_EQUAL(mk_bin(0x000005)==i, true); }
		{ item i{0x01,0x05}; BOOST_CHECK_EQUAL(mk_bin(0x000105)==i, true); }
		{ item i{0x81,0x05}; BOOST_CHECK_EQUAL(mk_bin(0x800105)==i, true); }

		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{mk_bin(0)},flags,stack_t{{}});
		test(script,stack_t{mk_bin((int64_t)INT_MAX+1)},flags,SCRIPT_ERR_INVALID_BIN2NUM_OPERATION);
		test(script,stack_t{mk_bin((int64_t)INT_MIN-1)},flags,SCRIPT_ERR_INVALID_BIN2NUM_OPERATION);
		test(script,stack_t{mk_bin((int64_t)INT_MAX)},flags,stack_t{mk_bin((int64_t)INT_MAX)});
		test(script,stack_t{mk_bin((int64_t)INT_MIN)},flags,stack_t{mk_bin((int64_t)INT_MIN)});

	}


	void test_cat(uint32_t flags) {
		CScript script;
		script << OP_CAT;

		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{0x00}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{0x00},{0x00}},flags,stack_t{{0x00,0x00}});
		test(script,stack_t{{0x01},{0x02}},flags,stack_t{{0x01,0x02}});

	}

	void test_split(uint32_t flags) {
		CScript script;
		script << OP_SPLIT;

		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{0x01}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{},{}},flags,stack_t{{},{}});
		test(script,stack_t{{0x01},{}},flags,stack_t{{},{0x01}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{}},flags,stack_t{{},{0x01,0x02,0x03,0x04}});

		test(script,stack_t{{0x01},{0x01}},flags,stack_t{{0x01},{}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{0x01}},flags,stack_t{{0x01},{0x02,0x03,0x04}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{0x02}},flags,stack_t{{0x01,0x02},{0x03,0x04}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{0x03}},flags,stack_t{{0x01,0x02,0x03},{0x04}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{0x04}},flags,stack_t{{0x01,0x02,0x03,0x04},{}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{0x05}},flags,SCRIPT_ERR_INVALID_SPLIT_RANGE);

	}

	void test_and(uint32_t flags) {
		CScript script;
		script << OP_AND;

		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{0x01}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{}},flags,stack_t{{}});


	}
	void test_or(uint32_t flags) {
		CScript script;
		script << OP_OR;

		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{0x01}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{}},flags,stack_t{{}});


	}
	void test_xor(uint32_t flags) {
		CScript script;
		script << OP_XOR;

		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{0x01}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{}},flags,stack_t{{}});


	}
	void test_div(uint32_t flags) {
		CScript script;
		script << OP_DIV;

		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{0x01}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{}},flags,stack_t{{}});


	}
	void test_mod(uint32_t flags) {
		CScript script;
		script << OP_MOD;

		test(script,stack_t(),flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{0x01}},flags,SCRIPT_ERR_INVALID_STACK_OPERATION);
		test(script,stack_t{{},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01},{}},flags,stack_t{{}});
		test(script,stack_t{{0x01,0x02,0x03,0x04},{}},flags,stack_t{{}});


	}

}

//BOOST_FIXTURE_TEST_SUITE(op_code, op_code_test)
BOOST_AUTO_TEST_SUITE(op_code)

BOOST_AUTO_TEST_CASE(op_cat) {
	test_cat(0);
	test_cat(STANDARD_SCRIPT_VERIFY_FLAGS);
	test_cat(STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
	test_cat(STANDARD_LOCKTIME_VERIFY_FLAGS);
}

BOOST_AUTO_TEST_CASE(op_split) {
	test_split(0);
	test_split(STANDARD_SCRIPT_VERIFY_FLAGS);
	test_split(STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
	test_split(STANDARD_LOCKTIME_VERIFY_FLAGS);
}
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
BOOST_AUTO_TEST_CASE(op_num2bin) {
	test_num2bin(0);
	test_num2bin(STANDARD_SCRIPT_VERIFY_FLAGS);
	test_num2bin(STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
	test_num2bin(STANDARD_LOCKTIME_VERIFY_FLAGS);
}

BOOST_AUTO_TEST_CASE(op_bin2num) {
	test_bin2num(0);
	test_bin2num(STANDARD_SCRIPT_VERIFY_FLAGS);
	test_bin2num(STANDARD_NOT_MANDATORY_VERIFY_FLAGS);
	test_bin2num(STANDARD_LOCKTIME_VERIFY_FLAGS);
}


BOOST_AUTO_TEST_SUITE_END()



