/*******************************************************************************
 * Copyright (c) 2012 Secure Software Engineering Group at EC SPRIDE.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser Public License v2.1
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *
 * Contributors: Christian Fritz, Steven Arzt, Siegfried Rasthofer, Eric
 * Bodden, and others.
 ******************************************************************************/
package soot.jimple.infoflow.android.callbacks;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import heros.solver.Pair;
import soot.AnySubType;
import soot.Body;
import soot.FastHierarchy;
import soot.Local;
import soot.PointsToSet;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.SootMethodRef;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.CastExpr;
import soot.jimple.ClassConstant;
import soot.jimple.FieldRef;
import soot.jimple.IdentityStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.ReturnVoidStmt;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.callbacks.AndroidCallbackDefinition.CallbackType;
import soot.jimple.infoflow.android.callbacks.filters.ICallbackFilter;
import soot.jimple.infoflow.android.entryPointCreators.AndroidEntryPointConstants;
import soot.jimple.infoflow.android.source.parsers.xml.ResourceUtils;
import soot.jimple.infoflow.entryPointCreators.SimulatedCodeElementTag;
import soot.jimple.infoflow.util.SootMethodRepresentationParser;
import soot.jimple.infoflow.util.SystemClassHandler;
import soot.jimple.infoflow.values.IValueProvider;
import soot.jimple.infoflow.values.SimpleConstantValueProvider;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraphFactory;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.util.HashMultiMap;
import soot.util.MultiMap;
import soot.jimple.infoflow.android.callbacks.filters.UnreachableConstructorFilter;
import soot.jimple.infoflow.android.callbacks.filters.ApplicationCallbackFilter;
import soot.jimple.infoflow.android.callbacks.filters.AlienHostComponentFilter;
import soot.jimple.NewExpr;

import java.util.Stack;

/**
 * Analyzes the classes in the APK file to find custom implementations of the
 * well-known Android callback and handler interfaces.
 *
 * @author Steven Arzt
 *
 */
public abstract class AbstractCallbackAnalyzer {

	protected final Logger logger = LoggerFactory.getLogger(getClass());

	protected final SootClass scContext = Scene.v().getSootClassUnsafe("android.content.Context");

	protected final SootClass activityCls = Scene.v().getSootClassUnsafe("android.app.Activity");
	protected final SootClass serviceCls = Scene.v().getSootClassUnsafe("android.app.Service");
	protected final SootClass providerCls = Scene.v().getSootClassUnsafe("android.content.ContentProvider");

	protected final SootClass scBroadcastReceiver = Scene.v()
			.getSootClassUnsafe(AndroidEntryPointConstants.BROADCASTRECEIVERCLASS);
	protected final SootClass scServiceConnection = Scene.v()
			.getSootClassUnsafe(AndroidEntryPointConstants.SERVICECONNECTIONINTERFACE);

	protected final SootClass scFragmentTransaction = Scene.v().getSootClassUnsafe("android.app.FragmentTransaction");
	protected final SootClass scFragment = Scene.v().getSootClassUnsafe(AndroidEntryPointConstants.FRAGMENTCLASS);

	protected final SootClass scSupportFragmentTransaction = Scene.v()
			.getSootClassUnsafe("android.support.v4.app.FragmentTransaction");
	protected final SootClass scAndroidXFragmentTransaction = Scene.v()
			.getSootClassUnsafe("androidx.fragment.app.FragmentTransaction");
	protected final SootClass scSupportFragment = Scene.v().getSootClassUnsafe("android.support.v4.app.Fragment");
	protected final SootClass scAndroidXFragment = Scene.v().getSootClassUnsafe("androidx.fragment.app.Fragment");

	protected final SootClass scFragmentStatePagerAdapter = Scene.v()
			.getSootClassUnsafe("android.support.v4.app.FragmentStatePagerAdapter");
	protected final SootClass scFragmentPagerAdapter = Scene.v()
			.getSootClassUnsafe("android.support.v4.app.FragmentPagerAdapter");

	protected final SootClass scAndroidXFragmentStatePagerAdapter = Scene.v()
			.getSootClassUnsafe("androidx.fragment.app.FragmentStatePagerAdapter");
	protected final SootClass scAndroidXFragmentPagerAdapter = Scene.v()
			.getSootClassUnsafe("androidx.fragment.app.FragmentPagerAdapter");

	protected final SootClass scAndroidXFragmentStateAdapter = Scene.v()
			.getSootClassUnsafe("androidx.viewpager2.adapter.FragmentStateAdapter");

	protected final SootClass viewGroup = Scene.v().getSootClassUnsafe("android.view.ViewGroup");
	protected final SootClass scViewClass = Scene.v().getSootClassUnsafe("android.view.View");

	protected final SootClass adapter = Scene.v().getSootClassUnsafe("android.widget.Adapter");
	protected final SootClass expandableListAdapter = Scene.v().getSootClassUnsafe("android.widget.ExpandableListAdapter");
	protected final SootClass spinnerAdapter = Scene.v().getSootClassUnsafe("android.widget.SpinnerAdapter");
	protected final SootClass simpleExpandableListAdapter = Scene.v().getSootClassUnsafe("android.widget.SimpleExpandableListAdapter");
	protected final SootClass resourceCursorTreeAdapter = Scene.v().getSootClassUnsafe("android.widget.ResourceCursorTreeAdapter");
	protected final SootClass cursorAdapter = Scene.v().getSootClassUnsafe("android.widget.CursorAdapter");

	protected final SootClass OnBackPressedCallback = Scene.v().getSootClassUnsafe("androidx.activity.OnBackPressedCallback");

	protected final InfoflowAndroidConfiguration config;
	protected final Set<SootClass> entryPointClasses;
	protected final Set<String> androidCallbacks;

	protected final MultiMap<SootClass, AndroidCallbackDefinition> callbackMethods = new HashMultiMap<>();
	protected final MultiMap<SootClass, Integer> layoutClasses = new HashMultiMap<>();
	protected final Set<SootClass> dynamicManifestComponents = new HashSet<>();
	protected final MultiMap<SootClass, SootClass> fragmentClasses = new HashMultiMap<>();
	protected final MultiMap<SootClass, SootClass> fragmentClassesRev = new HashMultiMap<>();
	protected MultiMap<SootClass, SootClass> globalFragmentClasses = new HashMultiMap<>(); // A reference to the fragmentClasses in SetupApplication

	public void setGlobalFragmentClasses(MultiMap<SootClass, SootClass> globalFragmentClasses) {
		this.globalFragmentClasses = globalFragmentClasses;
	}

	protected final List<ICallbackFilter> callbackFilters = new ArrayList<>();
	protected final Set<SootClass> excludedEntryPoints = new HashSet<>();

	protected IValueProvider valueProvider = new SimpleConstantValueProvider();

	protected List<String> activityNames = null;

	public void setActivityNames(List<String> activityNames) {
		this.activityNames = activityNames;
	}

	public abstract void setCallbackWorklist(MultiMap<SootClass, SootMethod> callbackWorklist);

	private Map<SootClass, MultiMap<String, SootClass>> callbackToBaseMap = new HashMap<>();

	public void addIntoCallbackToBaseMap(SootClass component, SootMethod callback, SootClass baseCls) {
		boolean cbDeclareInCompCls = activityCls != null && Scene.v().getFastHierarchy().canStoreType(callback.getDeclaringClass().getType(), activityCls.getType());
		cbDeclareInCompCls |= serviceCls != null && Scene.v().getFastHierarchy().canStoreType(callback.getDeclaringClass().getType(), serviceCls.getType());
		cbDeclareInCompCls |= providerCls != null && Scene.v().getFastHierarchy().canStoreType(callback.getDeclaringClass().getType(), providerCls.getType());
		cbDeclareInCompCls |= scBroadcastReceiver != null && Scene.v().getFastHierarchy().canStoreType(callback.getDeclaringClass().getType(), scBroadcastReceiver.getType());
		cbDeclareInCompCls |= scFragment != null && Scene.v().getFastHierarchy().canStoreType(callback.getDeclaringClass().getType(), scFragment.getType());
		cbDeclareInCompCls |= scSupportFragment != null && Scene.v().getFastHierarchy().canStoreType(callback.getDeclaringClass().getType(), scSupportFragment.getType());
		cbDeclareInCompCls |= scAndroidXFragment != null && Scene.v().getFastHierarchy().canStoreType(callback.getDeclaringClass().getType(), scAndroidXFragment.getType());
		if(cbDeclareInCompCls) return;
		MultiMap<String, SootClass> cbToBase = callbackToBaseMap.get(component);
		if(cbToBase == null) {
			cbToBase = new HashMultiMap<>();
			callbackToBaseMap.put(component, cbToBase);
		}
		cbToBase.put(callback.getSignature(), baseCls);
	}

	public Map<SootClass, MultiMap<String, SootClass>> getCallbackToBaseMap() {
		return callbackToBaseMap;
	}

	protected LoadingCache<SootField, List<Type>> arrayToContentTypes = CacheBuilder.newBuilder()
			.build(new CacheLoader<SootField, List<Type>>() {

				@Override
				public List<Type> load(SootField field) throws Exception {
					// Find all assignments to this field
					List<Type> typeList = new ArrayList<>();
					field.getDeclaringClass().getMethods().stream().filter(m -> m.isConcrete())
							.map(m -> m.retrieveActiveBody()).forEach(b -> {
								// Find all locals that reference the field
								Set<Local> arrayLocals = new HashSet<>();
								for (Unit u : b.getUnits()) {
									if (u instanceof AssignStmt) {
										AssignStmt assignStmt = (AssignStmt) u;
										Value rop = assignStmt.getRightOp();
										Value lop = assignStmt.getLeftOp();
										if (rop instanceof FieldRef && ((FieldRef) rop).getField() == field) {
											arrayLocals.add((Local) lop);
										} else if (lop instanceof FieldRef && ((FieldRef) lop).getField() == field) {
											arrayLocals.add((Local) rop);
										}
									}
								}

								// Find casts
								for (Unit u : b.getUnits()) {
									if (u instanceof AssignStmt) {
										AssignStmt assignStmt = (AssignStmt) u;
										Value rop = assignStmt.getRightOp();
										Value lop = assignStmt.getLeftOp();

										if (rop instanceof CastExpr) {
											CastExpr ce = (CastExpr) rop;
											if (arrayLocals.contains(ce.getOp()))
												arrayLocals.add((Local) lop);
											else if (arrayLocals.contains(lop))
												arrayLocals.add((Local) ce.getOp());
										}
									}
								}

								// Find the assignments to the array locals
								for (Unit u : b.getUnits()) {
									if (u instanceof AssignStmt) {
										AssignStmt assignStmt = (AssignStmt) u;
										Value rop = assignStmt.getRightOp();
										Value lop = assignStmt.getLeftOp();
										if (lop instanceof ArrayRef) {
											ArrayRef arrayRef = (ArrayRef) lop;
											if (arrayLocals.contains(arrayRef.getBase())) {
												Type t = rop.getType();
												if (t instanceof RefType)
													typeList.add(rop.getType());
											}
										}
									}
								}
							});
					return typeList;
				}

			});

	public AbstractCallbackAnalyzer(InfoflowAndroidConfiguration config, Set<SootClass> entryPointClasses)
			throws IOException {
		this(config, entryPointClasses, "AndroidCallbacks.txt");
	}

	public AbstractCallbackAnalyzer(InfoflowAndroidConfiguration config, Set<SootClass> entryPointClasses,
			String callbackFile) throws IOException {
		this(config, entryPointClasses, loadAndroidCallbacks(callbackFile));
	}

	public AbstractCallbackAnalyzer(InfoflowAndroidConfiguration config, Set<SootClass> entryPointClasses,
			InputStream inputStream) throws IOException {
		this(config, entryPointClasses, loadAndroidCallbacks(new InputStreamReader(inputStream)));
	}

	public AbstractCallbackAnalyzer(InfoflowAndroidConfiguration config, Set<SootClass> entryPointClasses,
			Reader reader) throws IOException {
		this(config, entryPointClasses, loadAndroidCallbacks(reader));
	}

	public AbstractCallbackAnalyzer(InfoflowAndroidConfiguration config, Set<SootClass> entryPointClasses,
			Set<String> androidCallbacks) throws IOException {
		this.config = config;
		this.entryPointClasses = entryPointClasses;
		this.androidCallbacks = androidCallbacks;
	}

	public void addAdditionalCallbacks(Set<String> additionalCallbacks) {
		for(String additionalCallback: additionalCallbacks) this.androidCallbacks.add(additionalCallback);
	}

	/**
	 * Loads the set of interfaces that are used to implement Android callback
	 * handlers from a file on disk
	 *
	 * @param androidCallbackFile The file from which to load the callback
	 *                            definitions
	 * @return A set containing the names of the interfaces that are used to
	 *         implement Android callback handlers
	 */
	private static Set<String> loadAndroidCallbacks(String androidCallbackFile) throws IOException {
		String fileName = androidCallbackFile;
		if (!new File(fileName).exists()) {
			fileName = "../soot-infoflow-android/AndroidCallbacks.txt";
			if (!new File(fileName).exists()) {
				try (InputStream is = ResourceUtils.getResourceStream("/AndroidCallbacks.txt")) {
					return loadAndroidCallbacks(new InputStreamReader(is));
				}
			}
		}
		try (FileReader fr = new FileReader(fileName)) {
			return loadAndroidCallbacks(fr);
		}
	}

	/**
	 * Loads the set of interfaces that are used to implement Android callback
	 * handlers from a file on disk
	 *
	 * @param reader A file reader
	 * @return A set containing the names of the interfaces that are used to
	 *         implement Android callback handlers
	 */
	public static Set<String> loadAndroidCallbacks(Reader reader) throws IOException {
		Set<String> androidCallbacks = new HashSet<String>();
		try (BufferedReader bufReader = new BufferedReader(reader)) {
			String line;
			while ((line = bufReader.readLine()) != null)
				if (!line.isEmpty())
					androidCallbacks.add(line);
		}
		return androidCallbacks;
	}

	/**
	 * Collects the callback methods for all Android default handlers implemented in
	 * the source code.
	 */
	public void collectCallbackMethods() {
		// Initialize the filters
		for (ICallbackFilter filter : callbackFilters)
			filter.reset();
	}

	private boolean matchSpecialCallbackParaRule(SootMethod mtd, int paraIndex) {
		if(mtd.getSignature().equals("<androidx.compose.runtime.internal.ComposableLambdaKt: androidx.compose.runtime.internal.ComposableLambda composableLambdaInstance(int,boolean,java.lang.Object)>") && paraIndex == 2) return true;
		if(mtd.getSignature().equals("<androidx.compose.runtime.internal.ComposableLambdaKt: androidx.compose.runtime.internal.ComposableLambda composableLambda(androidx.compose.runtime.Composer,int,boolean,java.lang.Object)>") && paraIndex == 3) return true;
		if(mtd.getSignature().equals("<android.text.Spannable: void setSpan(java.lang.Object,int,int,int)>") && paraIndex == 0) return true;
		if(mtd.getSignature().equals("<android.text.PrecomputedText: void setSpan(java.lang.Object,int,int,int)>") && paraIndex == 0) return true;
		if(mtd.getSignature().equals("<android.text.SpannableString: void setSpan(java.lang.Object,int,int,int)>") && paraIndex == 0) return true;
		if(mtd.getSignature().equals("<android.text.SpannableStringBuilder: void setSpan(java.lang.Object,int,int,int)>") && paraIndex == 0) return true;
		return false;
	}

	/**
	 * Analyzes the given method and looks for callback registrations
	 *
	 * @param lifecycleElement The lifecycle element (activity, etc.) with which to
	 *                         associate the found callbacks
	 * @param method           The method in which to look for callbacks
	 */
	protected void analyzeMethodForCallbackRegistrations(SootClass lifecycleElement, SootMethod method) {
		// Do not analyze system classes
		if (SystemClassHandler.v().isClassInSystemPackage(method.getDeclaringClass().getName()))
			return;
		if (!method.isConcrete())
			return;

		// Iterate over all statement and find callback registration methods
		Set<SootClass> callbackClasses = new HashSet<SootClass>();
		for (Unit u : method.retrieveActiveBody().getUnits()) {
			Stmt stmt = (Stmt) u;
			// Callback registrations may not necessarily be instance invoke expressions
			// E.g., staticinvoke <kotlinx.coroutines.BuildersKt: kotlinx.coroutines.Job launch$default(kotlinx.coroutines.CoroutineScope,kotlin.coroutines.CoroutineContext,int,kotlin.jvm.functions.Function2,int,java.lang.Object)>
			if (stmt.containsInvokeExpr()) {
				InvokeExpr iinv = stmt.getInvokeExpr();
				final SootMethodRef mref = iinv.getMethodRef();
				for (int i = 0; i < iinv.getArgCount(); i++) {
					final Type type = mref.getParameterType(i);
					if (!(type instanceof RefType))
						continue;
					String param = type.toString();
					if (androidCallbacks.contains(param) || matchSpecialCallbackParaRule(iinv.getMethod(), i)) {
						Value arg = iinv.getArg(i);
						// This call must be to a system API in order to
						// register an OS-level callback
						if (!SystemClassHandler.v()
								.isClassInSystemPackage(iinv.getMethod().getDeclaringClass().getName()))
							continue;
						// We have a formal parameter type that corresponds to one of the Android
						// callback interfaces. Look for definitions of the parameter to estimate the
						// actual type.
						if (arg instanceof Local) {
							Set<Type> possibleTypes = Scene.v().getPointsToAnalysis().reachingObjects((Local) arg).possibleTypes();
							for (Type possibleType : possibleTypes) {
								RefType baseType;
								if (possibleType instanceof RefType)
									baseType = (RefType) possibleType;
								else if (possibleType instanceof AnySubType)
									baseType = ((AnySubType) possibleType).getBase();
								else {
									logger.warn("Unsupported type detected in callback analysis");
									continue;
								}
								SootClass targetClass = baseType.getSootClass();
								if (!SystemClassHandler.v().isClassInSystemPackage(targetClass.getName())) callbackClasses.add(targetClass);
							}

							// If we don't have pointsTo information, we take
							// the type of the local
							if (possibleTypes.isEmpty()) {
								Type argType = ((Local) arg).getType();
								RefType baseType;
								if (argType instanceof RefType)
									baseType = (RefType) argType;
								else if (argType instanceof AnySubType)
									baseType = ((AnySubType) argType).getBase();
								else {
									logger.warn("Unsupported type detected in callback analysis");
									continue;
								}

								SootClass targetClass = baseType.getSootClass();
								if (!SystemClassHandler.v().isClassInSystemPackage(targetClass.getName()))
									callbackClasses.add(targetClass);
							}
						}
					}
				}
			}
		}

		Set<SootClass> components = findDeclaringComponents(method, false);
		// Analyze all found callback classes
		for (SootClass callbackClass : callbackClasses) {
			for(SootClass component: components) { // Check if the callback type can be initialized in methods that are reachable from the component, if not, the type resolved by pointsTo analysis may be a FP
				if(isReachableObj(component, callbackClass)) analyzeClassInterfaceCallbacks(callbackClass, callbackClass, component);
			}
		}
	}

	protected void analyzeMethodForAdapterViews(SootClass lifecycleElement, SootMethod method) {
		if (SystemClassHandler.v().isClassInSystemPackage(method.getDeclaringClass().getName())) return;

		if (!method.isConcrete()) return;

		boolean extendsAdapter = adapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), adapter.getType());
		extendsAdapter |= expandableListAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), expandableListAdapter.getType());
		extendsAdapter |= spinnerAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), spinnerAdapter.getType());
		extendsAdapter |= simpleExpandableListAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), simpleExpandableListAdapter.getType());
		extendsAdapter |= resourceCursorTreeAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), resourceCursorTreeAdapter.getType());
		extendsAdapter |= cursorAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), cursorAdapter.getType());

		if(! extendsAdapter) return;
		String subsubSig = method.getSubSignature().split(" ")[1];
		boolean isGetView = subsubSig.equals("getView(int,android.view.View,android.view.ViewGroup)");
		isGetView |= subsubSig.equals("getChildView(int,int,boolean,android.view.View,android.view.ViewGroup)");
		isGetView |= subsubSig.equals("getGroupView(int,boolean,android.view.View,android.view.ViewGroup)");
		isGetView |= subsubSig.equals("getDropDownView(int,android.view.View,android.view.ViewGroup)");
		isGetView |= subsubSig.equals("newChildView(boolean,android.view.ViewGroup)");
		isGetView |= subsubSig.equals("newGroupView(boolean,android.view.ViewGroup)");
		isGetView |= subsubSig.equals("newChildView(android.content.Context,android.database.Cursor,boolean,android.view.ViewGroup)");
		isGetView |= subsubSig.equals("newGroupView(android.content.Context,android.database.Cursor,boolean,android.view.ViewGroup)");
		isGetView |= subsubSig.equals("newDropDownView(android.content.Context,android.database.Cursor,android.view.ViewGroup)");
		isGetView |= subsubSig.equals("newView(android.content.Context,android.database.Cursor,android.view.ViewGroup)");

		boolean rtnView = scViewClass != null && Scene.v().getFastHierarchy().canStoreType(method.getReturnType(), scViewClass.getType());
		if(! isGetView || ! rtnView) return;

		Body body = method.retrieveActiveBody();

		if(body == null) return;

		Set<SootClass> components = findDeclaringComponents(method, false);
		for (Unit u : body.getUnits()) {
			if (u instanceof ReturnStmt) {
				ReturnStmt rs = (ReturnStmt) u;
				Value rv = rs.getOp();
				if (rv instanceof Local && rv.getType() instanceof RefType) {
					Set<Type> possibleTypes = Scene.v().getPointsToAnalysis().reachingObjects((Local) rv).possibleTypes();
					if(possibleTypes.isEmpty()) {
						for(SootClass component: components) checkAndAddViewCallbacks(component, ((RefType) rv.getType()).getSootClass());
					} else {
						for(Type possibleType: possibleTypes) {
							if(possibleType instanceof RefType) {
								for(SootClass component: components) {
									if(isReachableObj(component, ((RefType) possibleType).getSootClass())) checkAndAddViewCallbacks(component, ((RefType) possibleType).getSootClass());
								}
							} else if (possibleType instanceof AnySubType) {
								for(SootClass component: components) checkAndAddViewCallbacks(component, ((AnySubType) possibleType).getBase().getSootClass());
							}
						}
					}
				}
			}
		}
	}

	protected void analyzeMethodForAddView(SootClass lifecycleElement, SootMethod method) {
		// Do not analyze system classes
		if (SystemClassHandler.v().isClassInSystemPackage(method.getDeclaringClass().getName()))
			return;
		if (!method.isConcrete())
			return;

		// Iterate over all statement and find addView methods
		for (Unit u : method.retrieveActiveBody().getUnits()) {
			Stmt stmt = (Stmt) u;
			if(! stmt.containsInvokeExpr()) continue;
			InvokeExpr iExpr = stmt.getInvokeExpr();
			if(! (iExpr instanceof InstanceInvokeExpr)) continue;
			if(! Scene.v().getFastHierarchy().canStoreType(((InstanceInvokeExpr) iExpr).getBase().getType(), viewGroup.getType())) continue;
			boolean isAddView = iExpr.getMethod().getSubSignature().equals("void addView(android.view.View,android.view.ViewGroup$LayoutParams)");
			isAddView |= iExpr.getMethod().getSubSignature().equals("void addView(android.view.View,int)");
			isAddView |= iExpr.getMethod().getSubSignature().equals("void addView(android.view.View,int,android.view.ViewGroup$LayoutParams)");
			isAddView |= iExpr.getMethod().getSubSignature().equals("void addView(android.view.View)");
			isAddView |= iExpr.getMethod().getSubSignature().equals("void addView(android.view.View,int,int)");
			if(! isAddView) continue;
			Value view = iExpr.getArg(0);
			Set<SootClass> components = findDeclaringComponents(method, false);
			if(view instanceof Local) {
				Set<Type> possibleTypes = Scene.v().getPointsToAnalysis().reachingObjects((Local) view).possibleTypes();
				if(possibleTypes.isEmpty()) {
					if (!SystemClassHandler.v().isClassInSystemPackage(((RefType) view.getType()).getSootClass().getName()))
							for(SootClass component: components) checkAndAddViewCallbacks(component, ((RefType) view.getType()).getSootClass());
				} else {
					for(Type possibleType: possibleTypes) {
						if(possibleType instanceof RefType) {
							if (!SystemClassHandler.v().isClassInSystemPackage(((RefType) possibleType).getSootClass().getName())) {
								for(SootClass component: components) {
									if(isReachableObj(component, ((RefType) possibleType).getSootClass())) checkAndAddViewCallbacks(component, ((RefType) possibleType).getSootClass());
								}
							}
						} else if (possibleType instanceof AnySubType) {
							if (!SystemClassHandler.v().isClassInSystemPackage(((AnySubType) possibleType).getBase().getSootClass().getName()))
								for(SootClass component: components) checkAndAddViewCallbacks(component, ((AnySubType) possibleType).getBase().getSootClass());
						}
					}
				}
			}
		}
	}

	private void checkAndAddViewCallbacks(SootClass callbackClass, SootClass viewClass) {
		Map<String, SootMethod> systemMethods = new HashMap<>(10000);
		Set<SootClass> interfaces = collectAllInterfaces(viewClass);
		for(SootClass i: interfaces) {
			if(i.getName().startsWith("android.") || i.getName().startsWith("androidx.")) {
				for (SootMethod sm : i.getMethods())
					if (!sm.isConstructor() && !sm.isStatic() && !sm.isStaticInitializer() && !sm.isFinal() && !sm.isPrivate()) systemMethods.put(sm.getSubSignature(), sm);
			}
		}
		for (SootClass parentClass : Scene.v().getActiveHierarchy().getSuperclassesOf(viewClass)) {
			if (! SystemClassHandler.v().isClassInSystemPackage(parentClass.getName())) {
				Set<SootClass> is = collectAllInterfaces(parentClass);
				for(SootClass i: is) {
					if(i.getName().startsWith("android.") || i.getName().startsWith("androidx.")) {
						for (SootMethod sm : i.getMethods())
							if (!sm.isConstructor() && !sm.isStatic() && !sm.isStaticInitializer() && !sm.isFinal() && !sm.isPrivate()) systemMethods.put(sm.getSubSignature(), sm);
					}
				}
			}
			if (parentClass.getName().startsWith("android.") || parentClass.getName().startsWith("androidx."))
				for (SootMethod sm : parentClass.getMethods())
					if (!sm.isConstructor() && !sm.isStatic() && !sm.isStaticInitializer() && !sm.isFinal() && !sm.isPrivate())
						systemMethods.put(sm.getSubSignature(), sm);
		}
		// Scan for methods that overwrite parent class methods
		SootClass tmp = viewClass;
		while(true) {
			if(SystemClassHandler.v().isClassInSystemPackage(tmp.getName())) break;
			for (SootMethod sm : tmp.getMethods()) {
				if (!sm.isConstructor() && !sm.isStatic() && !sm.isStaticInitializer() && !sm.isPrivate()) {
					SootMethod parentMethod = systemMethods.get(sm.getSubSignature());
					if (parentMethod != null) {
						addIntoCallbackToBaseMap(callbackClass, sm, viewClass);
						this.callbackMethods.put(callbackClass, new AndroidCallbackDefinition(sm, parentMethod, CallbackType.Widget));
						systemMethods.remove(sm.getSubSignature());
					}
				}
			}
			if(tmp.hasSuperclass()) tmp = tmp.getSuperclass();
			else break;
		}
	}

	/**
	 * Checks whether all filters accept the association between the callback class
	 * and its parent component
	 *
	 * @param lifecycleElement The hosting component's class
	 * @param targetClass      The class implementing the callbacks
	 * @return True if all filters accept the given component-callback mapping,
	 *         otherwise false
	 */
	private boolean filterAccepts(SootClass lifecycleElement, SootClass targetClass) {
		for (ICallbackFilter filter : callbackFilters) 
			if (!filter.accepts(lifecycleElement, targetClass))
				return false;
		return true;
	}

	/**
	 * Checks whether all filters accept the association between the callback method
	 * and its parent component
	 *
	 * @param lifecycleElement The hosting component's class
	 * @param targetMethod     The method implementing the callback
	 * @return True if all filters accept the given component-callback mapping,
	 *         otherwise false
	 */
	private boolean filterAccepts(SootClass lifecycleElement, SootMethod targetMethod) {
		for (ICallbackFilter filter : callbackFilters)
			if (!filter.accepts(lifecycleElement, targetMethod))
				return false;
		return true;
	}

	/**
	 * Checks whether the given method dynamically registers a new broadcast
	 * receiver
	 *
	 * @param method The method to check
	 */
	protected void analyzeMethodForDynamicBroadcastReceiver(SootMethod method) {
		// Do not analyze system classes
		if (SystemClassHandler.v().isClassInSystemPackage(method.getDeclaringClass().getName()))
			return;
		if (!method.isConcrete() || !method.hasActiveBody())
			return;

		final FastHierarchy fastHierarchy = Scene.v().getFastHierarchy();
		final RefType contextType = scContext.getType();
		for (Unit u : method.getActiveBody().getUnits()) {
			Stmt stmt = (Stmt) u;
			if (stmt.containsInvokeExpr()) {
				final InvokeExpr iexpr = stmt.getInvokeExpr();
				final SootMethodRef methodRef = iexpr.getMethodRef();
				if (methodRef.getName().equals("registerReceiver") && iexpr.getArgCount() > 0
						&& fastHierarchy.canStoreType(methodRef.getDeclaringClass().getType(), contextType)) {
					Value br = iexpr.getArg(0);
					if (br.getType() instanceof RefType) {
						if(br instanceof Local) {
							Set<Type> possibleTypes = Scene.v().getPointsToAnalysis().reachingObjects((Local) br).possibleTypes();
							if(possibleTypes.isEmpty()) {
								if (!SystemClassHandler.v().isClassInSystemPackage(((RefType) br.getType()).getSootClass().getName()))
										dynamicManifestComponents.add(((RefType) br.getType()).getSootClass());
							} else {
								for(Type possibleType: possibleTypes) {
									if(possibleType instanceof RefType) {
										if (!SystemClassHandler.v().isClassInSystemPackage(((RefType) possibleType).getSootClass().getName()))
											dynamicManifestComponents.add(((RefType) possibleType).getSootClass());
									} else if (possibleType instanceof AnySubType) {
										if (!SystemClassHandler.v().isClassInSystemPackage(((AnySubType) possibleType).getBase().getSootClass().getName()))
											dynamicManifestComponents.add(((AnySubType) possibleType).getBase().getSootClass());
									}
								}
							}
						}
					}
				}
			}
		}
	}

	/**
	 * Checks whether the given method executes a fragment transaction that creates
	 * new fragment
	 *
	 * @author Goran Piskachev
	 * @param method The method to check
	 */
	protected void analyzeMethodForFragmentTransaction(SootClass lifecycleElement, SootMethod method) {
		if (SystemClassHandler.v().isClassInSystemPackage(method.getDeclaringClass().getName())) return;

		if (!method.isConcrete() || !method.hasActiveBody()) return;

		for (Unit u : method.getActiveBody().getUnits()) {
			Stmt stmt = (Stmt) u;
			if (stmt.containsInvokeExpr()) {
				final String className = stmt.getInvokeExpr().getMethod().getDeclaringClass().getName();
				final String methodName = stmt.getInvokeExpr().getMethod().getName();
				if(! className.equals("android.support.v4.app.FragmentTransaction") && ! className.equals("androidx.fragment.app.FragmentTransaction")) continue;
				if(! methodName.equals("add") && ! methodName.equals("replace")) continue;
				for (int i = 0; i < stmt.getInvokeExpr().getArgCount(); i++) {
					Value br = stmt.getInvokeExpr().getArg(i);

					if (br.getType() instanceof RefType) {
						RefType rt = (RefType) br.getType();
						if (br instanceof ClassConstant) rt = (RefType) ((ClassConstant) br).toSootType();

						boolean addFragment = scSupportFragment != null && Scene.v().getFastHierarchy().canStoreType(rt, scSupportFragment.getType());
						addFragment |= scAndroidXFragment != null && Scene.v().getFastHierarchy().canStoreType(rt, scAndroidXFragment.getType());
						if (addFragment) {
							// https://mailman.cs.mcgill.ca/pipermail/soot-list/2022-May/009310.html
							// checkAndAddFragment(method.getDeclaringClass(), rt.getSootClass());
							Set<SootClass> activities = findDeclaringComponents(method, true);
							if(br instanceof ClassConstant)
								for(SootClass activity: activities) checkAndAddFragment(activity, rt.getSootClass());
							else if(br instanceof Local) {
								Set<Type> possibleTypes = Scene.v().getPointsToAnalysis().reachingObjects((Local) br).possibleTypes();
								if(possibleTypes.isEmpty()) {
									for(SootClass activity: activities) checkAndAddFragment(activity, rt.getSootClass());
								} else {
									for(Type possibleType: possibleTypes) {
										if(possibleType instanceof RefType) {
											for(SootClass activity: activities) {
												Set<SootClass> frags = this.globalFragmentClasses.get(activity);
												boolean objReachable = isReachableObj(activity, ((RefType) possibleType).getSootClass());
												if(frags != null) {
													for(SootClass frag: frags) {
														objReachable |= isReachableObj(frag, ((RefType) possibleType).getSootClass());
													}
												}
												if(objReachable) checkAndAddFragment(activity, ((RefType) possibleType).getSootClass());
											}
										} else if (possibleType instanceof AnySubType) {
											for(SootClass activity: activities) checkAndAddFragment(activity, ((AnySubType) possibleType).getBase().getSootClass());
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	protected void analyzeMethodForFragmentShow(SootClass lifecycleElement, SootMethod method) {
		if (SystemClassHandler.v().isClassInSystemPackage(method.getDeclaringClass().getName())) return;

		if (!method.isConcrete() || !method.hasActiveBody()) return;

		for (Unit u : method.getActiveBody().getUnits()) {
			Stmt stmt = (Stmt) u;
			if (stmt.containsInvokeExpr()) {
				final String className = stmt.getInvokeExpr().getMethod().getDeclaringClass().getName();
				final String methodName = stmt.getInvokeExpr().getMethod().getName();
				if(! className.equals("androidx.fragment.app.DialogFragment") && ! className.equals("android.support.v4.app.DialogFragment")) continue;
				if(! methodName.equals("show") && ! methodName.equals("showNow")) continue;
				InvokeExpr invExpr = stmt.getInvokeExpr();
				if (invExpr instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr iinvExpr = (InstanceInvokeExpr) invExpr;
					Set<SootClass> activities = findDeclaringComponents(method, true);
					Set<Type> possibleTypes = Scene.v().getPointsToAnalysis().reachingObjects((Local) iinvExpr.getBase()).possibleTypes();
					if(possibleTypes.isEmpty()) {
						for(SootClass activity: activities) checkAndAddFragment(activity, ((RefType) iinvExpr.getBase().getType()).getSootClass());
					} else {
						for(Type possibleType: possibleTypes) {
							if(possibleType instanceof RefType) {
								for(SootClass activity: activities) {
									Set<SootClass> frags = this.globalFragmentClasses.get(activity);
									boolean objReachable = isReachableObj(activity, ((RefType) possibleType).getSootClass());
									if(frags != null) {
										for(SootClass frag: frags) {
											objReachable |= isReachableObj(frag, ((RefType) possibleType).getSootClass());
										}
									}
									if(objReachable) checkAndAddFragment(activity, ((RefType) possibleType).getSootClass());
								}
							} else if (possibleType instanceof AnySubType) {
								for(SootClass activity: activities) checkAndAddFragment(activity, ((AnySubType) possibleType).getBase().getSootClass());
							}
						}
					}
				}
			}
		}
	}

	private boolean isComponent(SootClass cls) {
		// return appComponents.contains(cls);
		boolean isComponent = activityCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(cls.getType(), activityCls.getType());
		isComponent |= serviceCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(cls.getType(), serviceCls.getType());
		isComponent |= scBroadcastReceiver != null && Scene.v().getOrMakeFastHierarchy().canStoreType(cls.getType(), scBroadcastReceiver.getType());
		isComponent |= providerCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(cls.getType(), providerCls.getType());
		isComponent |= scFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(cls.getType(), scFragment.getType());
		isComponent |= scAndroidXFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(cls.getType(), scAndroidXFragment.getType());
		isComponent |= scSupportFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(cls.getType(), scSupportFragment.getType());
		return isComponent;
	}

	private boolean outerClassNotMatchesComponent(Set<SootClass> appComponents, SootClass currComponent, SootClass topCls) {
		SootClass curCls = topCls;
		Set<SootClass> visited = new HashSet<>();
		while(curCls.isInnerClass()) {
			if(! visited.add(curCls)) break;
			if(Scene.v().getOrMakeFastHierarchy().canStoreType(currComponent.getType(), curCls.getType())) break;
			SootClass outerClass = curCls.getOuterClass();
			if(isComponent(outerClass) && ! Scene.v().getOrMakeFastHierarchy().canStoreType(currComponent.getType(), outerClass.getType())) return true;
			curCls = outerClass;
		}
		return false;
	}

	private boolean isLegalInterCompCalls(SootClass comp1, SootClass comp2) {
		boolean comp1IsActivity = activityCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp1.getType(), activityCls.getType());
		boolean comp2IsActivity = activityCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp2.getType(), activityCls.getType());
		boolean comp1IsService = serviceCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp1.getType(), serviceCls.getType());
		boolean comp2IsService = serviceCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp2.getType(), serviceCls.getType());
		boolean comp1IsReceiver = scBroadcastReceiver != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp1.getType(), scBroadcastReceiver.getType());
		boolean comp2IsReceiver = scBroadcastReceiver != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp2.getType(), scBroadcastReceiver.getType());
		boolean comp1IsProvider = providerCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp1.getType(), providerCls.getType());
		boolean comp2IsProvider = providerCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp2.getType(), providerCls.getType());
		boolean comp1IsFragment = scFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp1.getType(), scFragment.getType());
		comp1IsFragment |= scAndroidXFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp1.getType(), scAndroidXFragment.getType());
		comp1IsFragment |= scSupportFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp1.getType(), scSupportFragment.getType());
		boolean comp2IsFragment = scFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp2.getType(), scFragment.getType());
		comp2IsFragment |= scAndroidXFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp2.getType(), scAndroidXFragment.getType());
		comp2IsFragment |= scSupportFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(comp2.getType(), scSupportFragment.getType());
		if(comp1IsActivity && comp2IsService) return true;
		return false;
	}

	private boolean classNotMatchesComponent(Set<SootClass> appComponents, SootClass currComponent, SootClass topCls) {
		if(isComponent(topCls)) {
			if(isLegalInterCompCalls(currComponent, topCls)) return false; // We allow calls between different components (e.g., activity call service method)
			if(! Scene.v().getOrMakeFastHierarchy().canStoreType(currComponent.getType(), topCls.getType())) return true;
		}
		return false;
	}

	private boolean syntheticClassNotMatchesComponent(Set<SootClass> appComponents, SootClass currComponent, SootClass topCls) {
		if(! topCls.isInnerClass() && ((topCls.getModifiers() & soot.Modifier.SYNTHETIC) != 0) && topCls.getName().contains("$")) {
			// Class whose name contains "$$" may not be an inner class. E.g., ml.docilealligator.infinityforreddit.activities.MainActivity$$ExternalSyntheticLambda17
			String prefix = topCls.getName().split("\\$")[0];
			SootClass prefixCls = Scene.v().getSootClassUnsafe(prefix);
			if(prefixCls != null && isComponent(prefixCls) && ! Scene.v().getOrMakeFastHierarchy().canStoreType(currComponent.getType(), prefixCls.getType())) return true;
		}
		return false;
	}

	private boolean isBackMethod(SootMethod mtd) {
		if(SystemClassHandler.v().isClassInSystemPackage(mtd.getDeclaringClass().getName())) return false;
		String subSig = mtd.getSubSignature();
		if(activityCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(mtd.getDeclaringClass().getType(), activityCls.getType())) {
			if(subSig.equals("void onBackPressed()")) return true;
			if(subSig.equals("void onSaveInstanceState(android.os.Bundle)")) return true;
			if(subSig.equals("void onPause()")) return true;
			if(subSig.equals("void onStop()")) return true;
			if(subSig.equals("void onDestroy()")) return true;
		}
		if(serviceCls != null && Scene.v().getOrMakeFastHierarchy().canStoreType(mtd.getDeclaringClass().getType(), serviceCls.getType())) {
			if(subSig.equals("boolean onUnbind(android.content.Intent)")) return true;
			if(subSig.equals("void onDestroy()")) return true;
		}
		if((scFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(mtd.getDeclaringClass().getType(), scFragment.getType()))
		|| (scAndroidXFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(mtd.getDeclaringClass().getType(), scAndroidXFragment.getType()))
		|| (scSupportFragment != null && Scene.v().getOrMakeFastHierarchy().canStoreType(mtd.getDeclaringClass().getType(), scSupportFragment.getType()))) {
			if(subSig.equals("void onPause()")) return true;
			if(subSig.equals("void onStop()")) return true;
			if(subSig.equals("void onDestroyView()")) return true;
			if(subSig.equals("void onDestroy()")) return true;
			if(subSig.equals("void onDetach()")) return true;
			if(subSig.equals("void onSaveInstanceState(android.os.Bundle)")) return true;
		}
		if(OnBackPressedCallback != null && Scene.v().getOrMakeFastHierarchy().canStoreType(mtd.getDeclaringClass().getType(), OnBackPressedCallback.getType()) && mtd.getSubSignature().equals("void handleOnBackPressed()")) return true;
		
		return false;
	}

	private MultiMap<SootClass, String> compReachableMtds = new HashMultiMap<>(); // Each entry represents the set of reachable method from a component
	private MultiMap<SootClass, SootClass> compReachableObjs = new HashMultiMap<>(); // Each entry represents the set of class whose instance initialization is reachable from a component

	protected void reConstructCompReachableMtds() {
		this.compReachableMtds.clear();
		this.compReachableObjs.clear();

		Map<SootClass, SootMethod> components = new HashMap<>();
		SootClass dummyMainCls = Scene.v().getSootClassUnsafe("dummyMainClass");
		if(dummyMainCls == null) return;
		for(SootMethod mtd: dummyMainCls.getMethods()) {
			if(mtd.getName().startsWith("dummyMainMethod_")) {
				Type rtnType = mtd.getReturnType();
				if(rtnType instanceof RefType) {
					SootClass rtnCls = ((RefType) rtnType).getSootClass();
					components.put(rtnCls, mtd);
				}
			}
		}

		for(Map.Entry<SootClass, SootMethod> entry: components.entrySet()) {
			SootClass component = entry.getKey();
			SootMethod dummyMainMtd = entry.getValue();
			Stack<SootMethod> stack = new Stack<>();
			Stack<Boolean> isSingleOutEdgeStack = new Stack<>();
			Set<String> visited = new HashSet<>();
			stack.push(dummyMainMtd);
			isSingleOutEdgeStack.push(true);
			this.compReachableObjs.put(component, component); // Each component can new its self
			while(! stack.isEmpty()) {
				SootMethod top = stack.pop();
				boolean isSingleOutEdge = isSingleOutEdgeStack.pop();
				SootClass topCls = top.getDeclaringClass();
				if(! top.isStatic() && ! top.isConstructor() && ! top.isStaticInitializer() && ! isSingleOutEdge && outerClassNotMatchesComponent(components.keySet(), component, topCls)) continue;
				if(! top.isStatic() && ! top.isConstructor() && ! top.isStaticInitializer() && ! isSingleOutEdge && classNotMatchesComponent(components.keySet(), component, topCls)) continue;
				if(! top.isStatic() && ! top.isConstructor() && ! top.isStaticInitializer() && ! isSingleOutEdge && syntheticClassNotMatchesComponent(components.keySet(), component, topCls)) continue;
				// if(isBackMethod(top)) continue;
				String topClsName = topCls.getName();
				String topMtdName = top.getName();
				SootClass topMtdRtn = null;
				Type rtnType = top.getReturnType();
				if(rtnType instanceof RefType) topMtdRtn = ((RefType) rtnType).getSootClass();
				if(! top.equals(dummyMainMtd) && topClsName.equals("dummyMainClass") && topMtdName.startsWith("dummyMainMethod_") && topMtdRtn != null) continue;
				if(! visited.add(top.getSignature())) continue;
				if(! top.equals(dummyMainMtd)) this.compReachableMtds.put(component, top.getSignature());
				if(top.isConcrete() && ! topClsName.equals("dummyMainClass") && ! top.hasTag(SimulatedCodeElementTag.TAG_NAME)) {
					// Scan the method units to find object that are initialized and put its class into compReachableObjs
					Body body = top.retrieveActiveBody();
					if(body != null) {
						for(Unit u: body.getUnits()) {
							if(! (u instanceof AssignStmt)) continue;
							AssignStmt aStmt = (AssignStmt) u;
							if(! (aStmt.getRightOp() instanceof NewExpr)) continue;
							NewExpr nExpr = (NewExpr) aStmt.getRightOp();
							this.compReachableObjs.put(component, nExpr.getBaseType().getSootClass());
						}
					}
				}

				List<Pair<Unit, List<SootMethod>>> allowedCalleeAtUnitPairs = new ArrayList<>();
				List<Unit> units = new ArrayList<>();
				Iterator<Edge> edges = Scene.v().getCallGraph().edgesOutOf(top);
				while(edges.hasNext()) {
					Edge edge = edges.next();
					Unit unit = edge.srcUnit();
					if(unit == null) continue;
					if(units.contains(unit)) continue;
					units.add(unit);
					Stmt stmt = (Stmt) unit;
					if(stmt.containsInvokeExpr()) {
						SootMethod iMtd = stmt.getInvokeExpr().getMethod();
						if(iMtd.isConstructor() || iMtd.isStatic() || iMtd.isStaticInitializer()) continue;
						Pair<Unit, List<SootMethod>> pair = allowedCalleeAtUnit(component, iMtd, unit);
						if(pair != null) allowedCalleeAtUnitPairs.add(pair);
					}
				}

				edges = Scene.v().getCallGraph().edgesOutOf(top);
				while(edges.hasNext()) {
					Edge edge = edges.next();
					SootClass tgtCls = edge.tgt().getDeclaringClass();
					if(! tgtCls.getName().equals("dummyMainClass") && SystemClassHandler.v().isClassInSystemPackage(tgtCls.getName())) continue;
					
					boolean notAllowedAtUnit = false;
					if(edge.srcStmt() != null && edge.srcStmt().containsInvokeExpr() && edge.srcStmt().getInvokeExpr().getMethod().getName().equals(edge.tgt().getName())) {
						for(Pair<Unit, List<SootMethod>> pair: allowedCalleeAtUnitPairs) {
							if(pair.getO1().equals(edge.srcStmt()) && ! pair.getO2().contains(edge.tgt())) {
								notAllowedAtUnit = true;
								break;
							}
						}
					}
					if(notAllowedAtUnit) continue;
			
					int count = 0;
					if(edge.srcUnit() != null) {
						Iterator<Edge> itor = Scene.v().getCallGraph().edgesOutOf(edge.srcUnit());
						while(itor.hasNext()) {
							if(itor.next().tgt().getName().equals(edge.tgt().getName())) count++;
						}
					}
					stack.push(edge.tgt());
					if(count == 1) isSingleOutEdgeStack.push(true);
					else isSingleOutEdgeStack.push(false);
				}
			}
		}
	}

	private boolean isReachableObj(SootClass comp, SootClass obj) {
		Set<SootClass> reachableObjs = this.compReachableObjs.get(comp);
		return reachableObjs.contains(obj);
	}

	/*
	 * When the possible methods invoked from currComp at a callsite contains method declared in the component (including child classes) or its inner classes, other methods invoked 
	 * at the callsite are likely to be FPs
	 */
	private Pair<Unit, List<SootMethod>> allowedCalleeAtUnit(SootClass currComp, SootMethod iMtd, Unit callsite) {
		Iterator<Edge> itor = Scene.v().getCallGraph().edgesOutOf(callsite);
		List<SootMethod> allowedCallees = new ArrayList<>();
		while(itor.hasNext()) {
			Edge edge = itor.next();
			if(edge.tgt().getName().equals(iMtd.getName())) {
				SootClass cls = edge.tgt().getDeclaringClass();
				if(! SystemClassHandler.v().isClassInSystemPackage(cls.getName()) && isComponent(cls) && Scene.v().getOrMakeFastHierarchy().canStoreType(currComp.getType(), cls.getType())) {
					allowedCallees.add(edge.tgt());
					continue;
				}
				SootClass curCls = cls;
				Set<SootClass> visited = new HashSet<>();
				while(curCls.isInnerClass()) {
					if(! visited.add(curCls)) break;
					SootClass outerClass = curCls.getOuterClass();
					if(! SystemClassHandler.v().isClassInSystemPackage(outerClass.getName()) && isComponent(outerClass) && Scene.v().getOrMakeFastHierarchy().canStoreType(currComp.getType(), outerClass.getType())) {
						allowedCallees.add(edge.tgt());
						break;
					}
					curCls = outerClass;
				}

				if(! cls.isInnerClass() && ((cls.getModifiers() & soot.Modifier.SYNTHETIC) != 0) && cls.getName().contains("$")) {
					// Class whose name contains "$$" may not be an inner class. E.g., ml.docilealligator.infinityforreddit.activities.MainActivity$$ExternalSyntheticLambda17
					String prefix = cls.getName().split("\\$")[0];
					SootClass prefixCls = Scene.v().getSootClassUnsafe(prefix);
					if(prefixCls != null && ! SystemClassHandler.v().isClassInSystemPackage(prefix) && isComponent(prefixCls) && Scene.v().getOrMakeFastHierarchy().canStoreType(currComp.getType(), prefixCls.getType())) {
						allowedCallees.add(edge.tgt());
					}
				}
			}
		}
		if(allowedCallees.isEmpty()) return null;
		return new Pair<>(callsite, allowedCallees);
	}

	/*
	 * Finding the components that directly connects to the method. Further find the activities that contains the result fragments if onlyActivity is set to true
	 */
	protected Set<SootClass> findDeclaringComponents(SootMethod method, boolean onlyActivity) {
		Set<SootClass> rtnComponents = new HashSet<>();
		for(SootClass component: this.compReachableMtds.keySet()) {
			Set<String> reachableMtds = this.compReachableMtds.get(component);
			if(reachableMtds.contains(method.getSignature())) rtnComponents.add(component);
		}
		if(onlyActivity) {
			// For each fragment in the return components, find it container activity
			Set<SootClass> activitiesContainingFrags = new HashSet<>();
			Iterator<SootClass> itor = rtnComponents.iterator();
			while(itor.hasNext()) {
				SootClass rtnComp = itor.next();
				if(! this.activityNames.contains(rtnComp.getName())) {
					itor.remove();
					for(SootClass activity: this.globalFragmentClasses.keySet()) {
						for(SootClass frag: this.globalFragmentClasses.get(activity)) {
							if(rtnComp.equals(frag)) {
								activitiesContainingFrags.add(activity);
								break;
							}
						}
					}
				}
			}
			rtnComponents.addAll(activitiesContainingFrags);
		}
		return rtnComponents;
	}

	/**
	 * Check whether a method registers a FragmentStatePagerAdapter to a ViewPager.
	 * This pattern is very common for tabbed apps.
	 *
	 * @param clazz
	 * @param method
	 *
	 * @author Julius Naeumann
	 */
	protected void analyzeMethodForViewPagers(SootClass lifecycleElement, SootMethod method) {
		if (SystemClassHandler.v().isClassInSystemPackage(method.getDeclaringClass().getName())) return;

		if (!method.isConcrete()) return;

		boolean extendsAdapter = scFragmentStatePagerAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), scFragmentStatePagerAdapter.getType());
		extendsAdapter |= scAndroidXFragmentStatePagerAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), scAndroidXFragmentStatePagerAdapter.getType());
		extendsAdapter |= scFragmentPagerAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), scFragmentPagerAdapter.getType());
		extendsAdapter |= scAndroidXFragmentPagerAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), scAndroidXFragmentPagerAdapter.getType());
		extendsAdapter |= scAndroidXFragmentStateAdapter != null && Scene.v().getFastHierarchy().canStoreType(method.getDeclaringClass().getType(), scAndroidXFragmentStateAdapter.getType());

		if(! extendsAdapter) return;

		if(! method.getName().equals("getItem") && ! method.getName().equals("createFragment")) return;
		if(method.getParameterCount() != 1) return;
		if(! method.getParameterType(0).toString().equals("int")) return;
		boolean rtnFrag = scSupportFragment != null && Scene.v().getFastHierarchy().canStoreType(method.getReturnType(), scSupportFragment.getType());
		rtnFrag |= scAndroidXFragment != null && Scene.v().getFastHierarchy().canStoreType(method.getReturnType(), scAndroidXFragment.getType());

		if(! rtnFrag) return;

		Body body = method.retrieveActiveBody();

		if(body == null) return;

		Set<SootClass> activities = findDeclaringComponents(method, true);
		for (Unit u : body.getUnits()) {
			if (u instanceof ReturnStmt) {
				ReturnStmt rs = (ReturnStmt) u;
				Value rv = rs.getOp();
				if (rv instanceof Local && rv.getType() instanceof RefType) {
					Set<Type> possibleTypes = Scene.v().getPointsToAnalysis().reachingObjects((Local) rv).possibleTypes();
					if(possibleTypes.isEmpty()) {
						for(SootClass activity: activities) checkAndAddFragment(activity, ((RefType) rv.getType()).getSootClass());
					} else {
						for(Type possibleType: possibleTypes) {
							if(possibleType instanceof RefType) {
								for(SootClass activity: activities) {
									Set<SootClass> frags = this.globalFragmentClasses.get(activity);
									boolean objReachable = isReachableObj(activity, ((RefType) possibleType).getSootClass());
									if(frags != null) {
										for(SootClass frag: frags) {
											objReachable |= isReachableObj(frag, ((RefType) possibleType).getSootClass());
										}
									}
									if(objReachable) checkAndAddFragment(activity, ((RefType) possibleType).getSootClass());
								}
							} else if (possibleType instanceof AnySubType) {
								for(SootClass activity: activities) checkAndAddFragment(activity, ((AnySubType) possibleType).getBase().getSootClass());
							}
						}
					}
				}
			}
		}
	}

	/**
	 * Gets whether the call in the given statement can end up in the respective
	 * method inherited from one of the given classes.
	 *
	 * @param stmt       The statement containing the call sites
	 * @param classNames The base classes in which the call can potentially end up
	 * @return True if the given call can end up in a method inherited from one of
	 *         the given classes, otherwise falae
	 */
	protected boolean isInheritedMethod(Stmt stmt, String... classNames) {
		if (!stmt.containsInvokeExpr())
			return false;

		// Look at the direct callee
		SootMethod tgt = stmt.getInvokeExpr().getMethod();
		for (String className : classNames)
			if (className.equals(tgt.getDeclaringClass().getName()))
				return true;

		// If we have a callgraph, we can use that.
		if (Scene.v().hasCallGraph()) {
			Iterator<Edge> edgeIt = Scene.v().getCallGraph().edgesOutOf(stmt);
			while (edgeIt.hasNext()) {
				Edge edge = edgeIt.next();
				String targetClass = edge.getTgt().method().getDeclaringClass().getName();
				for (String className : classNames)
					if (className.equals(targetClass))
						return true;
			}
		}
		return false;
	}

	protected boolean invokesNewXActivity(InvokeExpr inv) {
		String sig = inv.getMethod().getSignature();
		if(sig.equals("<androidx.appcompat.app.AppCompatActivity: void <init>(int)>") || sig.equals("<androidx.fragment.app.FragmentActivity: void <init>(int)>") || sig.equals("<androidx.activity.ComponentActivity: void <init>(int)>")) return true;
		return false;
	}

	/**
	 * Checks whether this invocation calls Android's Activity.setContentView method
	 *
	 * @param inv The invocaton to check
	 * @return True if this invocation calls setContentView, otherwise false
	 */
	protected boolean invokesSetContentView(InvokeExpr inv) {
		String methodName = SootMethodRepresentationParser.v()
				.getMethodNameFromSubSignature(inv.getMethodRef().getSubSignature().getString());
		if (!methodName.equals("setContentView"))
			return false;

		// In some cases, the bytecode points the invocation to the current
		// class even though it does not implement setContentView, instead
		// of using the superclass signature
		SootClass curClass = inv.getMethod().getDeclaringClass();
		while (curClass != null) {
			final String curClassName = curClass.getName();
			if (curClassName.equals("android.app.Activity")
				|| curClassName.equals("android.support.v7.app.AppCompatActivity")
				|| curClassName.equals("androidx.appcompat.app.AppCompatActivity")
				|| curClassName.equals("androidx.activity.ComponentActivity"))
				return true;
			// As long as the class is subclass of android.app.Activity,
			// it can be sure that the setContentView method is what we expected.
			// Following 2 statements make the overriding of method
			// setContentView ignored.
			// if (curClass.declaresMethod("void setContentView(int)"))
			// return false;
			curClass = curClass.hasSuperclass() ? curClass.getSuperclass() : null;
		}
		return false;
	}

	/**
	 * Checks whether this invocation calls Android's LayoutInflater.inflate method
	 *
	 * @param inv The invocaton to check
	 * @return True if this invocation calls inflate, otherwise false
	 */
	protected boolean invokesInflate(InvokeExpr inv) {
		String methodName = SootMethodRepresentationParser.v()
				.getMethodNameFromSubSignature(inv.getMethodRef().getSubSignature().getString());
		if (!methodName.equals("inflate"))
			return false;
		// In some cases, the bytecode points the invocation to the current
		// class even though it does not implement setContentView, instead
		// of using the superclass signature
		SootClass curClass = inv.getMethod().getDeclaringClass();
		while (curClass != null) {
			final String curClassName = curClass.getName();
			if (curClassName.equals("android.view.LayoutInflater"))
				return true;
			curClass = curClass.hasSuperclass() ? curClass.getSuperclass() : null;
		}
		return false;
	}

	protected void analyzeMethodOverrideCallbacks(SootClass sootClass) {
		if (!sootClass.isConcrete())
			return;
		if (sootClass.isInterface())
			return;

		// Do not start the search in system classes
		if (config.getIgnoreFlowsInSystemPackages()
				&& SystemClassHandler.v().isClassInSystemPackage(sootClass.getName()))
			return;

		// There are also some classes that implement interesting callback
		// methods.
		// We model this as follows: Whenever the user overwrites a method in an
		// Android OS class, we treat it as a potential callback.
		Map<String, SootMethod> systemMethods = new HashMap<>(10000);
		for (SootClass parentClass : Scene.v().getActiveHierarchy().getSuperclassesOf(sootClass)) {
			if (SystemClassHandler.v().isClassInSystemPackage(parentClass.getName())) {
				for (SootMethod sm : parentClass.getMethods()) {
					if (!sm.isConstructor() && !sm.isStatic() && !sm.isStaticInitializer() && !sm.isFinal() && !sm.isPrivate())
						systemMethods.put(sm.getSubSignature(), sm);
				}
			}
		}

		// Iterate over all user-implemented methods. If they are inherited
		// from a system class, they are callback candidates.
		for (SootClass parentClass : Scene.v().getActiveHierarchy().getSuperclassesOfIncluding(sootClass)) {
			if (SystemClassHandler.v().isClassInSystemPackage(parentClass.getName()))
				continue;
			for (SootMethod method : parentClass.getMethods()) {
				if (!method.hasTag(SimulatedCodeElementTag.TAG_NAME)) {
					// Check whether this is a real callback method
					SootMethod parentMethod = systemMethods.get(method.getSubSignature());
					if (parentMethod != null) {
						if (checkAndAddMethod(method, parentMethod, sootClass, CallbackType.Default, sootClass)) {
							//We only keep the latest override in the class hierarchy
							systemMethods.remove(parentMethod.getSubSignature());
						}
					}
				}
			}
		}
	}

	private SootMethod getMethodFromHierarchyEx(SootClass c, String methodSignature) {
		SootMethod m = c.getMethodUnsafe(methodSignature);
		if (m != null)
			return m;
		SootClass superClass = c.getSuperclassUnsafe();
		if (superClass != null)
			return getMethodFromHierarchyEx(superClass, methodSignature);
		return null;
	}

	protected void analyzeClassInterfaceCallbacks(SootClass baseClass, SootClass sootClass,
			SootClass lifecycleElement) {
		// We cannot create instances of abstract classes anyway, so there is no
		// reason to look for interface implementations
		if (!baseClass.isConcrete())
			return;

		// Do not analyze system classes
		if (SystemClassHandler.v().isClassInSystemPackage(baseClass.getName()))
			return;
		if (SystemClassHandler.v().isClassInSystemPackage(sootClass.getName()))
			return;

		// Check the filters
		if (!filterAccepts(lifecycleElement, baseClass))
			return;
		if (!filterAccepts(lifecycleElement, sootClass))
			return;

		// If we are a class, one of our superclasses might implement an Android
		// interface
		SootClass superClass = sootClass.getSuperclassUnsafe();
		if (superClass != null)
			analyzeClassInterfaceCallbacks(baseClass, superClass, lifecycleElement);

		// Do we implement one of the well-known interfaces?
		for (SootClass i : collectAllInterfaces(sootClass)) {
			this.checkAndAddCallback(i, baseClass, lifecycleElement);
		}
		for (SootClass c : collectAllSuperClasses(sootClass)) {
			this.checkAndAddCallback(c, baseClass, lifecycleElement);
		}
	}

	/**
	 * Checks if the given class/interface appears in android Callbacks. If yes, add
	 * callback method to the list of callback methods
	 *
	 * @param sc               the class/interface to check for existence in
	 *                         AndroidCallbacks
	 * @param baseClass        the class implementing/extending sc
	 * @param lifecycleElement the component to which the callback method belongs
	 */
	private void checkAndAddCallback(SootClass sc, SootClass baseClass, SootClass lifecycleElement) {
		if (androidCallbacks.contains(sc.getName())) {
			CallbackType callbackType = isUICallback(sc) ? CallbackType.Widget : CallbackType.Default;
			for (SootMethod sm : sc.getMethods()) {
				SootMethod callbackImplementation = getMethodFromHierarchyEx(baseClass, sm.getSubSignature());
				if (callbackImplementation != null)
					checkAndAddMethod(callbackImplementation, sm, lifecycleElement, callbackType, baseClass);
			}
		}
	}

	/**
	 * Gets whether the given callback interface or class represents a UI callback
	 *
	 * @param i The callback interface or class to check
	 * @return True if the given callback interface or class represents a UI
	 *         callback, otherwise false
	 */
	private boolean isUICallback(SootClass i) {
		return i.getName().startsWith("android.widget") || i.getName().startsWith("android.view")
				|| i.getName().startsWith("android.content.DialogInterface$");
	}

	/**
	 * Checks whether the given Soot method comes from a system class. If not, it is
	 * added to the list of callback methods.
	 *
	 * @param method         The method to check and add
	 * @param parentMethod   The original method in the Android framework that
	 *                       declared the callback. This can, for example, be the
	 *                       method in the interface.
	 * @param lifecycleClass The base class (activity, service, etc.) to which this
	 *                       callback method belongs
	 * @param callbackType   The type of callback to be registered
	 * @return True if the method is new, i.e., has not been seen before, otherwise
	 *         false
	 */
	protected boolean checkAndAddMethod(SootMethod method, SootMethod parentMethod, SootClass lifecycleClass, CallbackType callbackType, SootClass baseCls) {
		// Do not call system methods
		if (SystemClassHandler.v().isClassInSystemPackage(method.getDeclaringClass().getName()))
			return false;

		// Skip empty methods
		if (method.isConcrete() && isEmpty(method.retrieveActiveBody()))
			return false;

		// Skip constructors
		if (method.isConstructor() || method.isStaticInitializer() || method.isStatic() || method.isPrivate())
			return false;

		// Check the filters
		if (!filterAccepts(lifecycleClass, method.getDeclaringClass()))
			return false;
		if (!filterAccepts(lifecycleClass, method))
			return false;

		boolean rtn = false;
		addIntoCallbackToBaseMap(lifecycleClass, method, baseCls);
		if(this.callbackMethods.put(lifecycleClass, new AndroidCallbackDefinition(method, parentMethod, callbackType))) rtn = true;
		if((method.getModifiers() & soot.Modifier.SYNTHETIC) != 0) {
			Body body = method.retrieveActiveBody();
			if(body != null) {
				for (Unit u : body.getUnits()) {
					Stmt stmt = (Stmt) u;
					if(! stmt.containsInvokeExpr()) continue;
					InvokeExpr iExpr = stmt.getInvokeExpr();
					SootMethod iMtd = iExpr.getMethod();
					if(iMtd.getDeclaringClass().equals(method.getDeclaringClass()) && iMtd.getName().equals(method.getName()) && iMtd.getParameterCount() == method.getParameterCount() && ! iMtd.getReturnType().toString().equals(method.getReturnType().toString())) {
						boolean allParaEquals = true;
						for(int i=0; i<iMtd.getParameterCount(); i++) {
							if(! iMtd.getParameterType(i).toString().equals(method.getParameterType(i).toString())) {
								allParaEquals = false;
								break;
							}
						}
						// When 2 methods are declared in the same class and they have the same name and same parameters but different return types, we put iMtd into the call graph because soot seems cannot handle this type of synthetic method
						if(allParaEquals) {
							addIntoCallbackToBaseMap(lifecycleClass, iMtd, baseCls);
							if(this.callbackMethods.put(lifecycleClass, new AndroidCallbackDefinition(iMtd, parentMethod, callbackType))) rtn = true;
						}
					}
				}
			}
		}

		return rtn;
	}

	/**
	 * Registers a fragment that belongs to a given component
	 *
	 * @param componentClass The component (usually an activity) to which the
	 *                       fragment belongs
	 * @param fragmentClass  The fragment class
	 */
	protected void checkAndAddFragment(SootClass componentClass, SootClass fragmentClass) {
		if(! fragmentClass.isConcrete()) return;
		if(SystemClassHandler.v().isClassInSystemPackage(fragmentClass.getName())) return;
		this.fragmentClasses.put(componentClass, fragmentClass);
		this.fragmentClassesRev.put(fragmentClass, componentClass);
	}

	private boolean isEmpty(Body activeBody) {
		for (Unit u : activeBody.getUnits())
			if (!(u instanceof IdentityStmt || u instanceof ReturnVoidStmt))
				return false;
		return true;
	}

	private Set<SootClass> collectAllInterfaces(SootClass sootClass) {
		Set<SootClass> interfaces = new HashSet<SootClass>(sootClass.getInterfaces());
		for (SootClass i : sootClass.getInterfaces())
			interfaces.addAll(collectAllInterfaces(i));
		return interfaces;
	}

	private Set<SootClass> collectAllSuperClasses(SootClass sootClass) {
		Set<SootClass> classes = new HashSet<SootClass>();
		if (sootClass.hasSuperclass()) {
			classes.add(sootClass.getSuperclass());
			classes.addAll(collectAllSuperClasses(sootClass.getSuperclass()));
		}
		return classes;
	}

	public MultiMap<SootClass, AndroidCallbackDefinition> getCallbackMethods() {
		return this.callbackMethods;
	}

	public MultiMap<SootClass, Integer> getLayoutClasses() {
		return this.layoutClasses;
	}

	public MultiMap<SootClass, SootClass> getFragmentClasses() {
		return this.fragmentClasses;
	}

	public Set<SootClass> getDynamicManifestComponents() {
		return this.dynamicManifestComponents;
	}

	/**
	 * Adds a new filter that checks every callback before it is associated with the
	 * respective host component
	 *
	 * @param filter The filter to add
	 */
	public void addCallbackFilter(ICallbackFilter filter) {
		this.callbackFilters.add(filter);
	}

	/**
	 * Excludes an entry point from all further processing. No more callbacks will
	 * be collected for the given entry point
	 *
	 * @param entryPoint The entry point to exclude
	 */
	public void excludeEntryPoint(SootClass entryPoint) {
		this.excludedEntryPoints.add(entryPoint);
	}

	/**
	 * Checks whether the given class is an excluded entry point
	 *
	 * @param entryPoint The entry point to check
	 * @return True if the given class is an excluded entry point, otherwise false
	 */
	public boolean isExcludedEntryPoint(SootClass entryPoint) {
		return this.excludedEntryPoints.contains(entryPoint);
	}

	/**
	 * Sets the provider that shall be used for obtaining constant values during the
	 * callback analysis
	 *
	 * @param valueProvider The value provider to use
	 */
	public void setValueProvider(IValueProvider valueProvider) {
		this.valueProvider = valueProvider;
	}

}
