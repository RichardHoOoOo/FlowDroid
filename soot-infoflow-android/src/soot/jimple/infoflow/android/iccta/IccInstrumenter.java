package soot.jimple.infoflow.android.iccta;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.Body;
import soot.Local;
import soot.LocalGenerator;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.Jimple;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.entryPointCreators.components.ComponentEntryPointCollection;
import soot.jimple.infoflow.entryPointCreators.SimulatedCodeElementTag;
import soot.jimple.infoflow.handlers.PreAnalysisHandler;
import soot.util.Chain;
import soot.util.HashMultiMap;
import soot.util.MultiMap;
import soot.Value;
import soot.Type;
import soot.RefLikeType;
import soot.jimple.NullConstant;
import soot.jimple.IntConstant;
import soot.jimple.LongConstant;
import soot.jimple.DoubleConstant;
import soot.jimple.FloatConstant;

public class IccInstrumenter implements PreAnalysisHandler {

	protected final Logger logger = LoggerFactory.getLogger(getClass());

	protected final String iccModel;
	protected final SootClass dummyMainClass;
	protected final ComponentEntryPointCollection componentToEntryPoint;

	protected IccRedirectionCreator redirectionCreator = null;

	protected final SootMethod smMessengerSend;
	protected final Set<SootMethod> processedMethods = new HashSet<>();
	protected final MultiMap<Body, Unit> instrumentedUnits = new HashMultiMap<>();

	protected List<String> handlerCallbackInfos = null;

	public void setHandlerCallbackInfos(List<String> handlerCallbackInfos) {
		this.handlerCallbackInfos = handlerCallbackInfos;
	}

	public IccInstrumenter(String iccModel, SootClass dummyMainClass,
			ComponentEntryPointCollection componentToEntryPoint) {
		this.iccModel = iccModel;
		this.dummyMainClass = dummyMainClass;
		this.componentToEntryPoint = componentToEntryPoint;

		// Fetch some Soot methods
		smMessengerSend = Scene.v().grabMethod("<android.os.Messenger: void send(android.os.Message)>");
	}

	@Override
	public void onBeforeCallgraphConstruction() {
		logger.info("[IccTA] Launching IccTA Transformer...");

		// Create the redirection creator
		if (redirectionCreator == null)
			redirectionCreator = new IccRedirectionCreator(dummyMainClass, componentToEntryPoint);
		else
			redirectionCreator.undoInstrumentation();

		// Remove any potential leftovers from the last last instrumentation
		undoInstrumentation();
		
		logger.info("[IccTA] Loading the ICC Model...");
		Ic3Provider provider = new Ic3Provider(iccModel);
		List<IccLink> iccLinks = provider.getIccLinks();
		logger.info("[IccTA] ...End Loading the ICC Model");

		logger.info("[IccTA] Lauching ICC Redirection Creation...");
		for (IccLink link : iccLinks) {
			if (link.fromU == null) {
				continue;
			}
			redirectionCreator.redirectToDestination(link);
		}

		// Instrument the messenger class
		instrumentMessenger();

		// Remove data that is no longer needed
		processedMethods.clear();

		logger.info("[IccTA] ...End ICC Redirection Creation");
	}

	/**
	 * Removes all units generated through instrumentation
	 */
	protected void undoInstrumentation() {
		for (Body body : instrumentedUnits.keySet()) {
			for (Unit u : instrumentedUnits.get(body)) {
				body.getUnits().remove(u);
			}
		}
		instrumentedUnits.clear();
	}

	private static Set<String> sendMessageMethods = new HashSet<>();

	static {
		sendMessageMethods.add("<android.os.Handler: void dispatchMessage(android.os.Message)>");
		sendMessageMethods.add("<android.os.Handler: boolean sendMessage(android.os.Message)>");
		sendMessageMethods.add("<android.os.Handler: boolean sendMessageAtFrontOfQueue(android.os.Message)>");
		sendMessageMethods.add("<android.os.Handler: boolean sendMessageAtTime(android.os.Message,long)>");
		sendMessageMethods.add("<android.os.Handler: boolean sendMessageDelayed(android.os.Message,long)>");
		sendMessageMethods.add("<android.os.Messenger: void send(android.os.Message)>");
	}

	protected void instrumentMessenger() {
		logger.info("Launching Messenger Transformer...");

		if(this.handlerCallbackInfos == null) return;
		for(String infoStr: this.handlerCallbackInfos) {
			HandlerCallbackInfo info = HandlerCallbackInfo.parse(infoStr);
			SootMethod container = info.getSinkMethod();
			int sequence = info.getSinkUnitID();
			List<SootMethod> callbacks = info.getCallbacks();

			final Body body = container.retrieveActiveBody();
			final LocalGenerator lg = Scene.v().createLocalGenerator(body);
			int i = 0;
			for (Iterator<Unit> unitIter = body.getUnits().snapshotIterator(); unitIter.hasNext();) {
				Stmt stmt = (Stmt) unitIter.next();
				if(! stmt.containsInvokeExpr()) continue;
				if(sendMessageMethods.contains(stmt.getInvokeExpr().getMethod().getSignature())) i++;
				if(i == sequence) {
					for(SootMethod callback: callbacks) {
						Local handlerLocal = lg.generateLocal(callback.getDeclaringClass().getType());

						Unit callHMU = Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(handlerLocal, callback.makeRef(), stmt.getInvokeExpr().getArg(0)));
						callHMU.addTag(SimulatedCodeElementTag.TAG);
						body.getUnits().insertAfter(callHMU, stmt);
						instrumentedUnits.put(body, callHMU);


						SootMethod initMethod = null;
						for(SootMethod mtd: callback.getDeclaringClass().getMethods()) {
							if(mtd.getName().equals("<init>")) {
								initMethod = mtd;
								break;
							}
						}
						List<Value> args = new ArrayList<>();
						for(Type paraType: initMethod.getParameterTypes()) {
							switch(paraType.toString()) {
								case "byte": args.add(IntConstant.v(0)); break;
								case "short": args.add(IntConstant.v(0)); break;
								case "int": args.add(IntConstant.v(0)); break;
								case "long": args.add(LongConstant.v(0)); break;
								case "float": args.add(FloatConstant.v(0)); break;
								case "double": args.add(DoubleConstant.v(0)); break;
								case "boolean": args.add(IntConstant.v(0)); break;
								case "char": args.add(IntConstant.v(0)); break;
								default: args.add(NullConstant.v()); break;
							}
						}
						Unit initU = Jimple.v().newInvokeStmt(Jimple.v().newSpecialInvokeExpr(handlerLocal, initMethod.makeRef(), args));
						initU.addTag(SimulatedCodeElementTag.TAG);
						body.getUnits().insertAfter(initU, stmt);
						instrumentedUnits.put(body, initU);

						Unit newU = Jimple.v().newAssignStmt(handlerLocal, Jimple.v().newNewExpr(callback.getDeclaringClass().getType()));
						newU.addTag(SimulatedCodeElementTag.TAG);
						body.getUnits().insertAfter(newU, stmt);
						instrumentedUnits.put(body, newU);
					}
					break;
				}
			}
		}
	}

	@Override
	public void onAfterCallgraphConstruction() {
		//
	}
}
