package edu.osu.seclab.utility;

import edu.osu.seclab.main.ApkContext;
import edu.osu.seclab.main.Config;

public class Logger {
	public static String TAG = "Logger";

	public static void printI(String args) {
		System.out.println(TAG + args);
	}

	public static void printW(String args) {
		String str = TAG + "[W]" + args;
		System.out.println(str);
		FileUtility.wf("./logs/warnning.txt", str, true);
	}

	public static void print(String args) {
		System.out.println(TAG + args);
	}

	public static void printE(String args) {
		args = TAG + args;
		FileUtility.wf("./logs/error.txt", args, true);
		System.out.println(args);
	}

	public static void printJSON(String args) {
		FileUtility.wf(Config.RESULTDIR + ApkContext.getInstance().getPackageName() + ".json", args, true);
	}

	public static void clearJSON() {
		FileUtility.wf(Config.RESULTDIR + ApkContext.getInstance().getPackageName() + ".json", "", false);
	}

}
