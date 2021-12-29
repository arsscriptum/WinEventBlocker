
//==============================================================================
//
//     cmdline.h
//
//============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================


#ifndef __CMDLINE_H__
#define __CMDLINE_H__

#include <vector>
#include <string>
#include <memory>

class CmdlineOption
{
public:
	CmdlineOption(std::vector<std::string> opt, std::string desc){
		options = opt;
		description = desc;
	};
	bool isValid(std::string option){
		for (auto&& str : options){
			if (str == option) { return true; }
		}
		return false;
	}
	bool operator == (const CmdlineOption & other) const
	{
		return options == other.options;
	}

	std::vector<std::string> options;
	std::string description;
};

// Class to manage program arguments
class CmdlineParser
{
public:
	CmdlineParser() {};
	void reset(int &argc,  char **argv)
	{
		for (int i = 1; i < argc; ++i) {
			this->tokens.push_back(std::string(argv[i]));
		}
	}

	const std::string& getCmdOption(const std::string &option) const {
		std::vector<std::string>::const_iterator itr;
		itr = std::find(this->tokens.begin(), this->tokens.end(), option);
		if (itr != this->tokens.end() && ++itr != this->tokens.end())
		{
			return *itr;
		}
		static const std::string empty_string("");
		return empty_string;
	}

	bool cmdOptionExists(const std::string &option) const
	{
		return std::find(this->tokens.begin(), this->tokens.end(), option) != this->tokens.end();
	}

	void addOption(CmdlineOption &cmdlineOption)
	{
		options.push_back(cmdlineOption);
	}
	bool isSet(CmdlineOption &cmdlineOption)
	{
		for (auto&& opt : cmdlineOption.options) {
			if (cmdOptionExists(opt) == true) {
				return true;
			}
		}
		return false;
	}
	bool invalidToken(){
		for (auto&& token : tokens){
			if (cmdlineOptionValid(token) == false) {
				return true;
			}
		}
		return false;
	}
private:
	bool cmdlineOptionValid(std::string opt)
	{
		for (auto&& elem : options){
			if (elem.isValid(opt)) {
				return true;
			}
		}
		return false;
	}
	std::vector <std::string> tokens;
	std::vector<CmdlineOption> options;
};

class CmdLineUtil
{
public:
	static CmdLineUtil* getInstance();

	void initializeCmdlineParser(int argc, char **argv);
	CmdlineParser *getInputParser() { return &inputParser; };

	void printTitle();
	void printDescription();
	void printSyntax();
	void printExamples();
	void printUsage();
	void errorCommands();

private:
	CmdLineUtil() {};

	CmdlineParser inputParser;
	static CmdLineUtil *instance;
};

#endif //__CMDLINE_H__