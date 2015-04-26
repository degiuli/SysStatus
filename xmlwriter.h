/*--
The MIT License (MIT)

Copyright (c) 2010-2013 De Giuli Informática Ltda. (http://www.degiuli.com.br)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
--*/

//ASCII: ANSI_X3.4-1968, ANSI_X3.4-1986, ASCII, ISO646-US, US-ASCII, ascii7, iso-ir-6, us, Windows-20127 
//Double Byte Character Set: GB2312.1980-0, chinese, gb2312-1980, iso-ir-58 
//HZ: HZ, HZ-GB-2312 
//ISO 2022: ISO-2022-CN, ISO-2022-CN-EXT, ISO-2022-JP, ISO-2022-JP-1, ISO-2022-JB-2, ISO-2022-KR, JIS, JIS7, JIS8, JIS_Encoding 
//LBMCS-1: LMBCS-1, lmbcs 
//LBMCS-2: LMBCS-2, lmbcs 
//LBMCS-3: LMBCS-3, lmbcs 
//LBMCS-4: LMBCS-4, lmbcs 
//LBMCS-5: LMBCS-5, lmbcs 
//LBMCS-6: LMBCS-6, lmbcs 
//LBMCS-8: LMBCS-8, lmbcs 
//LBMCS-11: LMBCS-11, lmbcs 
//LBMCS-16: LMBCS-16, lmbcs 
//LBMCS-17: LMBCS-17, lmbcs 
//LBMCS-18: LMBCS-18, lmbcs 
//LBMCS-19: LMBCS-19, lmbcs 
//Latin-1: ISO-8859-1, iso-ir-100, l1, latin1 
//Multi Byte Character Set: Big5, Big5-HKSCS, EUC-CN, EUC-JP, EUC-KR, EUC-TW, Extended_Unix_Code_Packed_for_Japanese, GB2312, GBK, HKSCS-BIG5, KSC_5601, KS_C_5601-1987, KS_C_5601-1989, MS936, MS_Kanji, Shift_JIS, X-EUC-JP, big5hk, cns11643, eucjis, gb18030, hp15CN, iso-ir-149, korean, ksc, macos-2566-10.2, ms932, ms949, pck, shift_jis78, sjis, sjis78, windows-31j, windows-51932, windows-51949, windows-54936, windows-932, windows-936, windows-936, windows-936-2000, windows-949, windows-949-2000, windows-950, windows-950-2000, x-big5, x-ms-cp932, x-sjis 
//Other: BOCU-1, CESU-8, IMAP-mailbox-name, iscii-bng, iscii-dev, iscii-guj, iscii-knd, iscii-mlm, iscii-ori, iscii-tlg, iscii-tlm, windows-57002, windows-57003, windows-57004. windows-57005, windows-57006, windows-57007, windows-57008, windows-57009, windows-57010, windows-57011, x-iscii-as, x-iscii-be, x-iscii-de, x-iscii-gu, x-iscii-ka, x-iscii-ma, x-iscii-or, x-iscii-pa, x-iscii-ta, x-iscii-te 
//SCSU: SCSU 
//Single Byte Character Set: ASMO-708, Adobe-Latin-1-Encoding, Adobe-Standard-Encoding, CCSID00858, CCSID01140, CCSID01141, CCSID01142, CCSID01143, CCSID01144, CCSID01145, CCSID01146, CCSID01147, CCSID01148, CCSID01149, DOS-862, EBCDIC-CP-DK, EBCDIC-CP-NO, EBCDIC-JP-kana, EMCA-114, EMCA-118, EMCA-128, ELOT_928, ISO-8859-6-E, ISO-8859-6-I, ISO-8859-8-E ISO-8859-8-i, JIS_X0201, K0I8-R, Latin-9, MS874, TIS-620, X0201, arabic, cyrillic, ebcdic-ar, ebcdic-ar-1, ebcdic-cp-ar1, ebcdic-cp-ar2, ebcdic-cp-be, ebcdic-cp-ca, ebcdic-cp-ch, ebcdic-cp-es, ebcdic-cp-fi, ebcdic-cp-fr, ebcdic-cp-gb, ebcdic-cp-he, ebcdic-cp-is, ebcdic-cp-it, ebcdic-cp-nl, ebcdic-cp-roece, ebcdic-cp-se, ebcdic-gb, ebcdic-he, ebcdic-is, ebcdic-sv, ebcdic-xml-us, eucTH, greek, greek8, hebrew, hp-roman8, iso-8859-13, iso-8859-15, iso-8859-2, iso-8859-3, iso-8859-4, iso-8859-5, iso-8859-6, iso-8859-7, iso-8859-8, iso-8859-9, iso-ir-101, iso-ir-109, iso-ir-110, iso-ir-126, iso-ir-127, iso-ir-138, iso-ir-144, iso-ir-148, iso8859_15_fdis, koi8, l2, l3, l4, l5, l9, latin0, latin2, latin3, latin4, latin5, mac, macce, maccy, macgr, macintosy, macos-0_2-10.2, macos-29-10.2, macos-35-10.2, macos-6-10.2, macos-7_3-10.2, mactr, r8, roman8, tis620.2533 
//UTF16: ISO-10646-UCS-2, UTF-16, UTF-16BE, UTF-16LE, UTF16_BigEndian, UTF16_LittleEndian, UTF16_OppositeEndian, UTF16_PlatformEndian, usc-2, unicode, windows-1200, windows-1201, x-utf-16be, x-utf-16le 
//UTF32: ISO-10646-UCS-4, UTF-32, UTF-32BE, UTF-32LE, UTF32_BigEndian, UTF32_LittleEndian, UTF32_OppositeEndian, UTF32_PlatformEndian, ucs-4 
//UTF7: UTF-7, Windows-65000 
//UTF8: UTF-8, Windows-65001

#ifndef xmlwriter_h
#define xmlwriter_h

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <stack>
using namespace std;
typedef stack<string> StackStrings;

typedef void (*DebugMsg)(char *message,int typeDebug);

class xmlwriter{
public:
	xmlwriter(string sTmp,DebugMsg dbg);
	~xmlwriter();
	void CreateChild(string sTag,string sValue);
	void Createtag(string sTag);
	void CloseLasttag();
	void CloseAlltags();
	void AddAtributes(string sAttrName, string sAttrvalue);
	void AddComment(string sComment);
private:
	string sXmlFile;
	vector<string> vectAttrData;
	FILE *fp;
	int iLevel;
	StackStrings sTagStack;

    DebugMsg pDebug;

    string validateTagName(string sTmp);
    string validateValue(string sTmp);
    void Write(int id,const char*format,...);
};

#endif // xmlwriter_h
