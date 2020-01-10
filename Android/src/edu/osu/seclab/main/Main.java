package edu.osu.seclab.main;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.zip.ZipException;

import edu.osu.seclab.base.GlobalStatistics;
import edu.osu.seclab.graph.CallGraph;
import edu.osu.seclab.graph.ValuePoint;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import soot.Scene;
import soot.options.Options;
import brut.androlib.AndrolibException;
import edu.osu.seclab.graph.DGraph;
import edu.osu.seclab.utility.FileUtility;
import edu.osu.seclab.utility.Logger;

public class Main {


	public static void startWatcher(int sec) {
		Thread t = new Thread() {
			public void run() {
				try {
					Thread.sleep(sec * 1000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Logger.printW("TimeOut");
				System.exit(1);
			}
		};
		t.setDaemon(true);
		t.start();
	}

	// args[0] app package name
	// args[1] config.json
	public static void main(String[] args) throws ZipException, IOException, AndrolibException {
		initDirs();

        // load configs
		InputStream is = new FileInputStream("./config.json");
		String jsonTxt = IOUtils.toString(is, "UTF-8");
		JSONObject json = new JSONObject(jsonTxt);

		Config.ANDROID_JAR_DIR = json.getString("ANDROID_JAR_DIR");

		Set<String> apps = new HashSet<>();
		JSONArray jsonArray = json.getJSONArray("APP_PATH");
		for (Object obj: jsonArray.toList()) {
			apps.add((String) obj);
		}

		HashMap<String, Integer> targs = new HashMap<>();
		JSONObject jsonObject = json.getJSONObject("API");
		for (String key: jsonObject.keySet()) {
			targs.put(key, jsonObject.getInt(key));
		}

        for(String apk: apps) {
			Logger.print("[*] Starting to analyze app: " + apk);

			ApkContext apkcontext = ApkContext.getInstance(apk);
			Logger.TAG = apkcontext.getPackageName();
			soot.G.reset();
			Options.v().set_src_prec(Options.src_prec_apk);
			Options.v().set_process_dir(Collections.singletonList(apkcontext.getAbsolutePath()));
			Options.v().set_force_android_jar(Config.ANDROID_JAR_DIR);
			Options.v().set_process_multiple_dex(true);
			Options.v().set_whole_program(true);
			Options.v().set_allow_phantom_refs(true);
			Options.v().set_output_format(Options.output_format_none);
			Options.v().ignore_resolution_errors();
			Scene.v().loadNecessaryClasses();


			long start = System.currentTimeMillis();
			startWatcher(Config.TIMEOUT);
			CallGraph.init();
			GlobalStatistics.getInstance().countSlicing(System.currentTimeMillis() - start);

			DGraph dg = new DGraph();

			List<ValuePoint> allvps = new ArrayList<ValuePoint>();
			List<ValuePoint> vps = null;


			for (String tsig : targs.keySet()) {
				List<Integer> regIndex = Arrays.asList(targs.get(tsig));
				vps = ValuePoint.find(dg, tsig, regIndex);
				for (ValuePoint vp : vps) {
					System.out.println(vp);
					vp.print();
				}
				allvps.addAll(vps);
			}

			dg.solve(allvps);

			Logger.print(GlobalStatistics.getInstance().printJsonResult().toString());
			GlobalStatistics.getInstance().clearData();
		}

        // finish all
		// write to file
		JSONObject results = GlobalStatistics.getInstance().getResults();
        Logger.clearJSON();
		Logger.printJSON(results.toString());
	}


	public static void initDirs() {
		File tmp = new File(Config.RESULTDIR);
		if (!tmp.exists())
			tmp.mkdir();
		tmp = new File(Config.LOGDIR);
		if (!tmp.exists())
			tmp.mkdir();
	}
}
