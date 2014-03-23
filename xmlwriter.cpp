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

// xmlwriter.cpp : Definiert den Einstiegspunkt für die Konsolenanwendung.
//

#include "xmlwriter.h"
#include <stdarg.h>

xmlwriter::xmlwriter(string sTmp,DebugMsg dbg)
{
    pDebug = dbg;

    sXmlFile = sTmp;
    fp = NULL;
    iLevel = 0;
    fp = fopen(sXmlFile.c_str(),"w");
    if(fp == NULL)
    {
		Write(__LINE__,"Unable to open output file");
		return;
  	}
	else
	{
		Write(__LINE__,"<?xml version=\"1.0\" encoding=\"UTF-8\"\?>");
	}
}

xmlwriter::~xmlwriter()
{
    if(fp != NULL)
        fclose(fp);
    vectAttrData.clear();
}

void xmlwriter::Createtag(string sTag)
{
    string tag = validateTagName(sTag);

	Write(__LINE__,"\n");
	//Indent properly
	for(int iTmp =0;iTmp<iLevel;iTmp++)
		Write(__LINE__,"\t");
	Write(__LINE__,"<%s",tag.c_str());
	//Add Attributes
	while(0 < vectAttrData.size()/2)
	{
		string sTmp = vectAttrData.back();
		Write(__LINE__," %s=", sTmp.c_str());
		vectAttrData.pop_back();
		sTmp = vectAttrData.back();
		Write(__LINE__,"\"%s\"", sTmp.c_str());
		vectAttrData.pop_back();
	}
	vectAttrData.clear();
	Write(__LINE__,">");
	sTagStack.push(tag);
	iLevel++;

}

void xmlwriter::CloseLasttag()
{
	Write(__LINE__,"\n");
	iLevel--;
    //Indent properly
	for(int iTmp =0;iTmp<iLevel;iTmp++)
		Write(__LINE__,"\t");
	Write(__LINE__,"</%s>",sTagStack.top().c_str());
	sTagStack.pop();//pop out the last tag
	return;
}

void xmlwriter::CloseAlltags()
{
	while(sTagStack.size() != 0)
	{
	   Write(__LINE__,"\n");
	   iLevel--;
        //Indent properly
	   for(int iTmp =0;iTmp<iLevel;iTmp++)
	       Write(__LINE__,"\t");
	   Write(__LINE__,"</%s>",sTagStack.top().c_str());
	   sTagStack.pop();//pop out the last tag
    }
	return;
}

void xmlwriter::CreateChild(string sTag,string sValue)
{
    string tag = validateTagName(sTag);
    string value = validateValue(sValue);

	Write(__LINE__,"\n");
	//Indent properly
	for(int iTmp =0;iTmp<iLevel;iTmp++)
		Write(__LINE__,"\t");
	Write(__LINE__,"<%s",tag.c_str());
	//Add Attributes
	while(0 < vectAttrData.size()/2)
	{
		string sTmp = vectAttrData.back();
		Write(__LINE__," %s=", sTmp.c_str());
		vectAttrData.pop_back();
		sTmp = vectAttrData.back();
		Write(__LINE__,"\"%s\"", sTmp.c_str());
		vectAttrData.pop_back();
	}
	vectAttrData.clear();
	//add value and close tag
	Write(__LINE__,">%s</%s>",value.c_str(),tag.c_str());
}

void xmlwriter::AddAtributes(string sKey, string sVal)
{
	vectAttrData.push_back(validateValue(sVal));
	vectAttrData.push_back(validateTagName(sKey));
}

void xmlwriter::AddComment(string sComment)
{
	Write(__LINE__,"\n");
	//Indent properly
	for(int iTmp =0;iTmp<iLevel;iTmp++)
		Write(__LINE__,"\t");
	Write(__LINE__,"<!-- %s -->",sComment.c_str());
}

string xmlwriter::validateTagName(string sTmp)
{
    string temp;
    char * str = new char[sTmp.size()+1];
    memset(str,0x00,sizeof(char)*sTmp.size()+1);
    strcpy(str,sTmp.c_str());

    //first character must be a alphabetic one
    //if(isalpha(str[0]))
    if((str[0]>=0x41 && str[0]<=0x5A) ||
       (str[0]>=0x61 && str[0]<=0x7A))
    {
        temp.assign(sTmp);
    }
    else
    {
        temp.assign("a_");
        temp.append(sTmp);
    }
    delete [] str;
    return validateValue(temp);
}

string xmlwriter::validateValue(string sTmp)
{
    char validSpecChars[] = {
        '!',    '@',    '#',    '$',    '%',
        '*',    '(',    ')',    '-',    '_',
        '/',    '|',    '\\',   '\"',   '\'',
        ',',    '.',    ';',    ':',    '[',
        ']',    '{',    '}',    '=',    '+',
        '?',    '^',    '~',    0x20,   0x00
    };

    char * str = new char[sTmp.size()+1];
    memset(str,0x00,sizeof(char)*sTmp.size()+1);
    strcpy(str,sTmp.c_str());

    int newSize = sTmp.size()*5+1;
    char * newStr = new char[newSize];
    memset(newStr,0x00,sizeof(char)*newSize);

    int i = 0, pos = 0;

    while(str[i]!=NULL)
    {
        //if(isalnum(str[i]) || str[i]==0x20)
        if((str[i]>=0x41 && str[i]<=0x5A) ||
           (str[i]>=0x61 && str[i]<=0x7A) ||
           (str[i]>=0x30 && str[i]<=0x39))
        {
            newStr[pos] = str[i];
            pos++;
        }
        else if(str[i]=='&')
        {
            pos += _snprintf(&newStr[pos],newSize-pos-1,"&amp;",str[i]);
        }
        //else if(ispunct(str[i]) && str[i]!=0x60)
        //{
        //    newStr[pos] = str[i];
        //    pos++;
        //}
        //else
        //{
        //    pos += _snprintf(&newStr[pos],newSize-pos-1,"&#%d;",str[i]);
        //}
        else
        {
            int x = 0;
            bool found = false;
            while(validSpecChars[x]!=0x00)
            {
                if(str[i]==validSpecChars[x])
                {
                    newStr[pos] = str[i];
                    pos++;
                    found = true;
                    break;
                }
                x++;
            }

            if(!found)
            {
                pos += _snprintf(&newStr[pos],newSize-pos-1,"&#%d;",str[i]);
            }
        }
        i++;
    }

    string temp(newStr);

    delete [] str;
    delete [] newStr;

    return temp;
}

void xmlwriter::Write(int id,const char*format,...)
{
    char message[3000] = {0};
    char buffer[2048] = {0};
    va_list	argptr;

    //Format the message to be logged
    va_start(argptr,format);
    if(fp)
    {
        vfprintf(fp,format,argptr);
    }

    //Write debug
    _vsnprintf(buffer,sizeof(buffer)-1,format,argptr);
    if(strlen(buffer)>2)    //do not write CR/LF
    {
        _snprintf(message,sizeof(message),"TID %.5u ID %.5u -- XmlWritter: %s\r\n",GetCurrentThreadId(),id,buffer);
        (*pDebug)(message,0/*LOG_NONE*/);
    }
    va_end(argptr);
}
