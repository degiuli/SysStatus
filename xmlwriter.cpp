/*--
The MIT License (MIT)

Copyright (c) 2010-2019 De Giuli Informática Ltda. (http://www.degiuli.com.br)

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

// xmlwriter.cpp : Definiert den Einstiegspunkt für die Konsolenanwendung.
//

#include "xmlwriter.h"

#include <cstdarg>
#include <memory>

xmlwriter::xmlwriter(std::string const& sTmp, DebugMsg dbg) : sXmlFile(sTmp), pDebug(dbg), iLevel(0)
{
    iLevel = 0;
    fp = fopen(sXmlFile.c_str(), "w");
    if (fp == nullptr)
    {
        Write(__LINE__, "Unable to open output file");
        return;
    }
    else
    {
        Write(__LINE__, "<?xml version=\"1.0\" encoding=\"UTF-8\"\?>");
    }
}

xmlwriter::~xmlwriter()
{
    if (fp != NULL)
        fclose(fp);
    vectAttrData.clear();
}

void xmlwriter::Createtag(std::string const& sTag)
{
    std::string tag = validateTagName(sTag);

    Write(__LINE__, "\n");

    //Indent properly
    for (int iTmp = 0; iTmp < iLevel; iTmp++)
        Write(__LINE__, "\t");

    Write(__LINE__, "<%s", tag.c_str());

    //Add Attributes
    while (0 < vectAttrData.size() / 2)
    {
        std::string sTmp = vectAttrData.back();
        Write(__LINE__, " %s=", sTmp.c_str());
        vectAttrData.pop_back();
        sTmp = vectAttrData.back();
        Write(__LINE__, "\"%s\"", sTmp.c_str());
        vectAttrData.pop_back();
    }

    vectAttrData.clear();
    Write(__LINE__, ">");
    sTagStack.push(tag);
    iLevel++;
}

void xmlwriter::CloseLasttag()
{
    Write(__LINE__, "\n");
    iLevel--;

    //Indent properly
    for (int iTmp = 0; iTmp < iLevel; iTmp++)
        Write(__LINE__, "\t");

    Write(__LINE__, "</%s>", sTagStack.top().c_str());
    sTagStack.pop();//pop out the last tag
    return;
}

void xmlwriter::CloseAlltags()
{
    while (sTagStack.size() != 0)
    {
        Write(__LINE__, "\n");
        iLevel--;

        //Indent properly
        for (int iTmp = 0; iTmp < iLevel; iTmp++)
            Write(__LINE__, "\t");

        Write(__LINE__, "</%s>", sTagStack.top().c_str());
        sTagStack.pop();//pop out the last tag
    }
    return;
}

void xmlwriter::CreateChild(std::string const& sTag, std::string const& sValue)
{
    std::string tag = validateTagName(sTag);
    std::string value = validateValue(sValue);

    Write(__LINE__, "\n");

    //Indent properly
    for (int iTmp = 0; iTmp < iLevel; iTmp++)
        Write(__LINE__, "\t");

    Write(__LINE__, "<%s", tag.c_str());

    //Add Attributes
    while (0 < vectAttrData.size() / 2)
    {
        std::string sTmp = vectAttrData.back();
        Write(__LINE__, " %s=", sTmp.c_str());
        vectAttrData.pop_back();
        sTmp = vectAttrData.back();
        Write(__LINE__, "\"%s\"", sTmp.c_str());
        vectAttrData.pop_back();
    }

    vectAttrData.clear();

    //add value and close tag
    Write(__LINE__, ">%s</%s>", value.c_str(), tag.c_str());
}

void xmlwriter::AddAtributes(std::string const& sKey, std::string const& sVal)
{
    vectAttrData.push_back(validateValue(sVal));
    vectAttrData.push_back(validateTagName(sKey));
}

void xmlwriter::AddComment(std::string const& sComment)
{
    Write(__LINE__, "\n");

    //Indent properly
    for (int iTmp = 0; iTmp < iLevel; iTmp++)
        Write(__LINE__, "\t");

    Write(__LINE__, "<!-- %s -->", sComment.c_str());
}

std::string xmlwriter::validateTagName(std::string const& sTemp)
{
    std::string temp;

    //first character must be a alphabetic one
    if ((sTemp[0] >= 0x41 && sTemp[0] <= 0x5A) ||
        (sTemp[0] >= 0x61 && sTemp[0] <= 0x7A))
    {
        temp.assign(sTemp);
    }
    else
    {
        temp.assign("a_");
        temp.append(sTemp);
    }
    return validateValue(temp);
}

std::string xmlwriter::validateValue(std::string const& sTmp)
{
    char const validSpecChars[] = {
        '!',    '@',    '#',    '$',    '%',
        '*',    '(',    ')',    '-',    '_',
        '/',    '|',    '\\',   '\"',   '\'',
        ',',    '.',    ';',    ':',    '[',
        ']',    '{',    '}',    '=',    '+',
        '?',    '^',    '~',    0x20,   0x00
    };

    size_t const newSize = (sTmp.size() * 5) + 1;
    std::unique_ptr<char[]> newStr(new char[newSize]);
    memset(&newStr[0], 0x00, sizeof(char) * newSize);

    int pos = 0;
    for(char const ch : sTmp)
    {
        if ((ch >= 0x41 && ch <= 0x5A) ||
            (ch >= 0x61 && ch <= 0x7A) ||
            (ch >= 0x30 && ch <= 0x39))
        {
            newStr[pos] = ch;
            pos++;
        }
        else if (ch == '&')
        {
            pos += _snprintf(&newStr[pos], newSize - pos - 1, "&amp;"); // , ch);
        }
        else
        {
            int x = 0;
            bool found = false;
            while (validSpecChars[x] != 0x00)
            {
                if (ch == validSpecChars[x])
                {
                    newStr[pos] = ch;
                    pos++;
                    found = true;
                    break;
                }
                x++;
            }

            if (!found)
            {
                pos += _snprintf(&newStr[pos], newSize - pos - 1, "&#%d;", ch);
            }
        }
    }

    return std::string(newStr.get());
}

void xmlwriter::Write(int id, const char*format, ...)
{
    char buffer[2048] = { 0 };
    va_list	argptr;

    //Format the message to be logged
    va_start(argptr, format);
    if (fp)
    {
        vfprintf(fp, format, argptr);
    }

    //Write debug
    if (_vsnprintf(buffer, sizeof(buffer) - 1, format, argptr) > 2)    //do not write CR/LF
    {
        char message[3000] = { 0 };
        _snprintf(message, sizeof(message), "TID %.5u ID %.5i -- XmlWritter: %s\r\n", GetCurrentThreadId(), id, buffer);
        (*pDebug)(message, 0/*LOG_NONE*/);
    }
    va_end(argptr);
}
