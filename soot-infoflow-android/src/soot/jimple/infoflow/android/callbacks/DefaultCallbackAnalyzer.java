package soot.jimple.infoflow.android.callbacks;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import heros.solver.Pair;
import soot.MethodOrMethodContext;
import soot.PackManager;
import soot.RefType;
import soot.Type;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Local;
import soot.Unit;
import soot.Value;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.callbacks.AndroidCallbackDefinition.CallbackType;
import soot.jimple.infoflow.android.callbacks.filters.ICallbackFilter;
import soot.jimple.infoflow.android.entryPointCreators.AndroidEntryPointConstants;
import soot.jimple.infoflow.android.entryPointCreators.AndroidEntryPointUtils;
import soot.jimple.infoflow.memory.IMemoryBoundedSolver;
import soot.jimple.infoflow.memory.ISolverTerminationReason;
import soot.jimple.infoflow.util.SystemClassHandler;
import soot.util.HashMultiMap;
import soot.util.MultiMap;
import soot.util.queue.QueueReader;

/**
 * Default implementation of the callback analyzer class. This implementation
 * aims for precision. It tries to rule out callbacks registered in unreachable
 * code. The mapping between components and callbacks is as precise as possible.
 * 
 * @author Steven Arzt
 *
 */
public class DefaultCallbackAnalyzer extends AbstractCallbackAnalyzer implements IMemoryBoundedSolver {

	private MultiMap<SootClass, SootMethod> callbackWorklist = null;
	private AndroidEntryPointUtils entryPointUtils = new AndroidEntryPointUtils();
	private Set<IMemoryBoundedSolverStatusNotification> notificationListeners = new HashSet<>();
	private ISolverTerminationReason isKilled = null;
	private MultiMap<SootClass, AndroidCallbackDefinition> viewCallbacks;


	public DefaultCallbackAnalyzer(InfoflowAndroidConfiguration config, Set<SootClass> entryPointClasses)
			throws IOException {
		super(config, entryPointClasses);
	}

	public DefaultCallbackAnalyzer(InfoflowAndroidConfiguration config, Set<SootClass> entryPointClasses,
			MultiMap<SootClass, AndroidCallbackDefinition> viewCallbacks, String callbackFile) throws IOException {
		super(config, entryPointClasses, callbackFile);
		this.viewCallbacks = viewCallbacks;
	}

	public DefaultCallbackAnalyzer(InfoflowAndroidConfiguration config, Set<SootClass> entryPointClasses,
			MultiMap<SootClass, AndroidCallbackDefinition> viewCallbacks, Set<String> androidCallbacks)
			throws IOException {
		super(config, entryPointClasses, androidCallbacks);
		this.viewCallbacks = viewCallbacks;
	}

	QueueReader<MethodOrMethodContext> reachableChangedListener;

	private Set<SootClass> alreadyAnalyzeFragmentEntries = new HashSet<>();

	public void setCallbackWorklist(MultiMap<SootClass, SootMethod> callbackWorklist) {
		this.callbackWorklist = callbackWorklist;
	}

	/**
	 * Collects the callback methods for all Android default handlers implemented in
	 * the source code. Note that this operation runs inside Soot, so this method
	 * only registers a new phase that will be executed when Soot is next run
	 */
	@Override
	public void collectCallbackMethods() {
		super.collectCallbackMethods();

		Transform transform = new Transform("wjtp.ajc", new SceneTransformer() {
			@Override
			protected void internalTransform(String phaseName, @SuppressWarnings("rawtypes") Map options) {
				// Notify the listeners that the solver has been started
				for (IMemoryBoundedSolverStatusNotification listener : notificationListeners)
					listener.notifySolverStarted(DefaultCallbackAnalyzer.this);

				// Do we have to start from scratch or do we have a worklist to
				// process?
				if (callbackWorklist == null) {
					logger.info("Collecting callbacks in DEFAULT mode...");
					reConstructCompReachableMtds();
					callbackWorklist = new HashMultiMap<>();

					// Find the mappings between classes and layouts
					findClassLayoutMappings();

					// Process the callback classes directly reachable from the
					// entry points
					for (SootClass sc : entryPointClasses) {
						// Check whether we're still running
						if (isKilled != null)
							break;

						List<MethodOrMethodContext> methods = new ArrayList<MethodOrMethodContext>(
								entryPointUtils.getLifecycleMethods(sc));

						// Check for callbacks registered in the code
						analyzeReachableMethods(sc, methods);

						// Check for method overrides
						analyzeMethodOverrideCallbacks(sc);
						analyzeClassInterfaceCallbacks(sc, sc, sc);
					}
					reachableChangedListener = Scene.v().getReachableMethods().listener();
					connectUnconnectedCallbacks();
					logger.info("Callback analysis done.");
				} else {
					reConstructCompReachableMtds();
					// Find the mappings between classes and layouts
					findClassLayoutMappings();


					// Add the methods that have become reachable in the views
					MultiMap<SootMethod, SootClass> reverseViewCallbacks = new HashMultiMap<>();
					for (Pair<SootClass, AndroidCallbackDefinition> i : viewCallbacks)
						reverseViewCallbacks.put(i.getO2().getTargetMethod(), i.getO1());
					reachableChangedListener = Scene.v().getReachableMethods().listener();
					while (reachableChangedListener.hasNext()) {
						SootMethod m = reachableChangedListener.next().method();
						Set<SootClass> o = reverseViewCallbacks.get(m);
						for (SootClass i : o) {
							callbackWorklist.put(i, m);
						}
					}

					// Put fragments callbacks into the worklist since they are never included in the viewCallbacks if fragments does not contain xml callbacks or view callbacks
					for(SootClass activityCls: globalFragmentClasses.keySet()) {
						for(SootClass fragCls: globalFragmentClasses.get(activityCls)) {
							if(! alreadyAnalyzeFragmentEntries.add(fragCls)) continue;
							List<MethodOrMethodContext> lcs = new ArrayList<MethodOrMethodContext>(entryPointUtils.getLifecycleMethods(fragCls));
							if(! lcs.isEmpty()) {
								for(MethodOrMethodContext lc: lcs) {
									callbackWorklist.put(fragCls, lc.method());
								}
							} else {
								callbackWorklist.put(fragCls, null); // In case no lifecycle callbacks are found in obfuscated app, we forcely add the fragment into the list
							}
						}
					}

					// Incremental mode, only process the worklist
					logger.info(String.format("Running incremental callback analysis for %d components...",
							callbackWorklist.size()));

					MultiMap<SootClass, SootMethod> workList = new HashMultiMap<>(callbackWorklist);
					for (Iterator<SootClass> it = workList.keySet().iterator(); it.hasNext();) {
						// Check whether we're still running
						if (isKilled != null)
							break;

						SootClass componentClass = it.next();
						Set<SootMethod> callbacks = callbackWorklist.get(componentClass);
						callbackWorklist.remove(componentClass);

						Set<SootClass> activityComponents = fragmentClassesRev.get(componentClass);
						if (activityComponents == null || activityComponents.isEmpty())
							activityComponents = Collections.singleton(componentClass);

						// Check whether we're already beyond the maximum number
						// of callbacks for the current component
						if (config.getCallbackConfig().getMaxCallbacksPerComponent() > 0
								&& callbacks.size() > config.getCallbackConfig().getMaxCallbacksPerComponent()) {
							callbackMethods.remove(componentClass);
							entryPointClasses.remove(componentClass);
							continue;
						}

						// Check for method overrides. The whole class might be new.
						analyzeMethodOverrideCallbacks(componentClass);
						for (SootClass activityComponent : activityComponents) {
							if (activityComponent == null)
								activityComponent = componentClass;
							analyzeClassInterfaceCallbacks(componentClass, componentClass, activityComponent);
						}

						// Collect all methods that we need to analyze
						List<MethodOrMethodContext> entryClasses = new ArrayList<>(callbacks.size());
						for (SootMethod sm : callbacks) {
							if (sm != null)
								entryClasses.add(sm);
						}

						// Check for further callback declarations
						analyzeReachableMethods(componentClass, entryClasses);
					}
					connectUnconnectedCallbacks();
					logger.info("Incremental callback analysis done.");
				}

				// Notify the listeners that the solver has been terminated
				for (IMemoryBoundedSolverStatusNotification listener : notificationListeners)
					listener.notifySolverTerminated(DefaultCallbackAnalyzer.this);
			}

		});
		PackManager.v().getPack("wjtp").add(transform);
	}

	private void analyzeReachableMethods(SootClass lifecycleElement, List<MethodOrMethodContext> methods) {
		// Make sure to exclude all other edges in the callgraph except for the
		// edges start in the lifecycle methods we explicitly pass in
		ComponentReachableMethods rm = new ComponentReachableMethods(config, lifecycleElement, methods, butterknifeUnbinderCls);
		rm.update();

		// Scan for listeners in the class hierarchy
		QueueReader<MethodOrMethodContext> reachableMethods = rm.listener();
		while (reachableMethods.hasNext()) {
			// Check whether we're still running
			if (isKilled != null)
				break;

			for (ICallbackFilter filter : callbackFilters)
				filter.setReachableMethods(rm);

			SootMethod method = reachableMethods.next().method();
			if (method.isConcrete()) {
				analyzeMethodForCallbackRegistrations(lifecycleElement, method);
				analyzeMethodForDynamicBroadcastReceiver(method);
				analyzeMethodForFragmentTransaction(lifecycleElement, method);
				analyzeMethodForPrefFragment(lifecycleElement, method);
				analyzeMethodForFragmentShow(lifecycleElement, method);
				analyzeMethodForViewPagers(lifecycleElement, method);
				analyzeMethodForAddView(lifecycleElement, method);
				analyzeMethodForAdapterViews(lifecycleElement, method);
			}
		}
	}

	@Override
	protected boolean checkAndAddMethod(SootMethod method, SootMethod parentMethod, SootClass lifecycleClass, CallbackType callbackType, SootClass baseCls) {
		if (!this.excludedEntryPoints.contains(lifecycleClass)) {
			if (super.checkAndAddMethod(method, parentMethod, lifecycleClass, callbackType, baseCls)) {
				// Has this entry point been excluded?
				this.callbackWorklist.put(lifecycleClass, method);
				return true;
			}
		}
		return false;
	}

	@Override
	protected boolean checkAndAddFragment(SootClass componentClass, SootClass fragmentClass) {
		boolean rtn = false;
		if (!this.excludedEntryPoints.contains(componentClass)) {
			rtn = super.checkAndAddFragment(componentClass, fragmentClass);

			for (SootMethod sm : fragmentClass.getMethods()) {
				if (sm.isConstructor()
						|| AndroidEntryPointConstants.getFragmentLifecycleMethods().contains(sm.getSubSignature()))
					callbackWorklist.put(fragmentClass, sm);
			}
		}
		return rtn;
	}

	Iterator<MethodOrMethodContext> rmIterator;

	/**
	 * Finds the mappings between classes and their respective layout files
	 */
	private void findClassLayoutMappings() {
		// if (rmIterator == null)
			rmIterator = Scene.v().getReachableMethods().listener();
		while (rmIterator.hasNext()) {
			SootMethod sm = rmIterator.next().method();
			if (!sm.isConcrete())
				continue;
			if (SystemClassHandler.v().isClassInSystemPackage(sm.getDeclaringClass().getName()))
				continue;
			for (Unit u : sm.retrieveActiveBody().getUnits()) {
				if (u instanceof Stmt) {
					Stmt stmt = (Stmt) u;
					if (stmt.containsInvokeExpr()) {
						InvokeExpr inv = stmt.getInvokeExpr();
						if (invokesSetContentView(inv) || invokesNewXActivity(inv)) {
							for (Value val : inv.getArgs()) {
								Integer intValue = valueProvider.getValue(sm, stmt, val, Integer.class);
								if (intValue != null) {
									Set<SootClass> activities = findDeclaringComponents(sm, true);
									for(SootClass activity: activities)
										this.layoutClasses.put(activity, intValue);
								}

							}
						}
						if(invokesDataBindingUtilSetContentView(inv)) {
							Integer intValue = valueProvider.getValue(sm, stmt, inv.getArg(1), Integer.class);
							if (intValue != null && inv.getArg(0) instanceof Local) {
								Set<Type> possibleTypes = Scene.v().getPointsToAnalysis().reachingObjects((Local) inv.getArg(0)).possibleTypes();
								for(Type possibleType: possibleTypes) {
									if(possibleType instanceof RefType) {
										SootClass actCls = ((RefType) possibleType).getSootClass();
										boolean extendsActivity = activityCls != null && Scene.v().getFastHierarchy().canStoreType(possibleType, activityCls.getType());
										if(! extendsActivity) continue;
										if(! actCls.isConcrete()) continue;
										if(SystemClassHandler.v().isClassInSystemPackage(actCls.getName())) continue;
										this.layoutClasses.put(actCls, intValue);
									}
								}	
							}
						}
						if (invokesInflate(inv)) {
							Integer intValue = valueProvider.getValue(sm, stmt, inv.getArg(0), Integer.class);
							if (intValue != null) {
								Set<SootClass> components = findDeclaringComponents(sm, false);
								for(SootClass component: components) 
									this.layoutClasses.put(component, intValue);
							}
						}
						if (invokesDataBindingInflate(inv)) {
							Integer intValue = valueProvider.getValue(sm, stmt, inv.getArg(1), Integer.class);
							if (intValue != null) {
								Set<SootClass> components = findDeclaringComponents(sm, false);
								for(SootClass component: components) 
									this.layoutClasses.put(component, intValue);
							}
						}
						if (invokesSetPreferencesFromResource(inv)) {
							Integer intValue = valueProvider.getValue(sm, stmt, inv.getArg(0), Integer.class);
							if (intValue != null) {
								Set<SootClass> components = findDeclaringComponents(sm, false);
								for(SootClass component: components) 
									this.layoutClasses.put(component, intValue);
							}
						}
					}
				}
			}
		}
	}

	@Override
	public void forceTerminate(ISolverTerminationReason reason) {
		this.isKilled = reason;
	}

	@Override
	public boolean isTerminated() {
		return isKilled != null;
	}

	@Override
	public boolean isKilled() {
		return isKilled != null;
	}

	@Override
	public void reset() {
		this.isKilled = null;
	}

	@Override
	public void addStatusListener(IMemoryBoundedSolverStatusNotification listener) {
		this.notificationListeners.add(listener);
	}

	@Override
	public void excludeEntryPoint(SootClass entryPoint) {
		super.excludeEntryPoint(entryPoint);
		this.callbackWorklist.remove(entryPoint);
		this.callbackMethods.remove(entryPoint);
	}

	@Override
	public ISolverTerminationReason getTerminationReason() {
		return isKilled;
	}

}
