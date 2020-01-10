package edu.osu.seclab.base;

import org.json.JSONObject;

public class GlobalStatistics {
	static GlobalStatistics gs = new GlobalStatistics();

	static JSONObject results = new JSONObject();

	private GlobalStatistics() {
	}

	public static GlobalStatistics getInstance() {
		return gs;
	}

	public void countGetString() {
		getString++;
	}

	public void countAppendString() {
		appendString++;
	}

	public void countFormatString() {
		formatString++;
	}

	public void countDiveIntoMethodCall() {
		diveIntoMethodCall++;
	}

	public void countBackWard2Caller() {
		backWard2Caller++;
	}

	public void updateMaxCallStack(int i) {
		if (i > maxCallStack)
			maxCallStack = i;
	}

	int getString = 0;
	int appendString = 0;
	int formatString = 0;
	int diveIntoMethodCall = 0;
	int backWard2Caller = 0;
	int maxCallStack = 0;

	int total = 0;
	int argument = 0;
	int ui = 0;
	int model = 0;

	long slicingTime = 0;
	long executionTime = 0;
	int branch = 0;
	int instr = 0;


	public void countTotal() {++total;}

	public void countArgument() {++argument;}

	public void countUI() {++ui;}

	public void countModel() {++model;}

	public void countBranch(int b) {branch += b;}

	public void countInstr(int i) {instr += i;}

	public void countSlicing(long s) {slicingTime += s;}

	public void countExec(long e) {executionTime += e;}

	public int getTotal() {return total;}

	public long getSlicing() {return slicingTime;}

	public JSONObject getResults() {return results;}

	public JSONObject toJson() {
		JSONObject result = new JSONObject();
		result.put("getString", getString);
		result.put("appendString", appendString);
		result.put("formatString", formatString);
		result.put("diveIntoMethodCall", diveIntoMethodCall);
		result.put("backWard2Caller", backWard2Caller);
		result.put("maxCallStack", maxCallStack);
		return result;
	}

	public void clearData() {
		total = 0;
		argument = 0;
		ui = 0;
		model = 0;
		slicingTime = 0;
		executionTime = 0;
		branch = 0;
		instr = 0;
	}

	public JSONObject printJsonResult(){
		JSONObject res = new JSONObject();
		res.put("Total", total);
		res.put("Argument", argument);
		res.put("UI", ui);
		res.put("Model", model);
		res.put("Slicing Cost", ((double)slicingTime)/1000);
		res.put("Branch", branch);
		res.put("Execution Cost", ((double)executionTime)/1000);
		res.put("Instr", instr);
		return res;
	}
}
