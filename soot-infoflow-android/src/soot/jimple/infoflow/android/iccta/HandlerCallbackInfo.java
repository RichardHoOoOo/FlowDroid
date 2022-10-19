package soot.jimple.infoflow.android.iccta;

import soot.SootMethod;
import soot.Scene;
import java.util.List;
import java.util.ArrayList;

public class HandlerCallbackInfo {

	public SootMethod sinkMtd; // The method that contains sinkIMtd
	public SootMethod sinkIMtd; // The send message invocation (handler.sendMessage(Message))
	public int sinkUnitID;
	public List<SootMethod> callbacks;
	
	public HandlerCallbackInfo(SootMethod sinkMtd, SootMethod sinkIMtd, int sinkUnitID, List<SootMethod> callbacks) {
		this.sinkMtd = sinkMtd;
		this.sinkIMtd = sinkIMtd;
		this.sinkUnitID = sinkUnitID;
		this.callbacks = callbacks;
	}

	public static HandlerCallbackInfo parse(String str) {
		String[] pair = str.split("=>");
		String[] pair0 = pair[0].split(";");
		String[] pair1 = pair[1].split(";");
		List<SootMethod> callbacks = new ArrayList<>();
		for(String cbSig: pair1) callbacks.add(Scene.v().getMethod(cbSig));
		return new HandlerCallbackInfo(Scene.v().getMethod(pair0[0]), Scene.v().getMethod(pair0[1]), Integer.parseInt(pair0[2]), callbacks);
	}

	public SootMethod getSinkMethod() {
		return this.sinkMtd;
	}

	public int getSinkUnitID() {
		return this.sinkUnitID;
	}

	public List<SootMethod> getCallbacks() {
		return this.callbacks;
	}
	
}