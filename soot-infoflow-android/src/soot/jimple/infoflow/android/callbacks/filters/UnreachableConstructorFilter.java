package soot.jimple.infoflow.android.callbacks.filters;

import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.android.entryPointCreators.AndroidEntryPointConstants;

import java.util.Set;
import java.util.HashSet;

/**
 * Filter for ruling out objects for which no factory method or allocation site
 * is reachable in the current component
 * 
 * @author Steven Arzt
 *
 */
public class UnreachableConstructorFilter extends AbstractCallbackFilter {

	@Override
	public boolean accepts(SootClass component, SootClass callbackHandler) {
		// If we have no reachability information, there is nothing we can do
		if (reachableMethods == null)
			return true;

		// If the callback is in the component class itself, it is trivially reachable
		if (component == callbackHandler)
			return true;

		SootClass xfragmentClass = Scene.v().getSootClassUnsafe(AndroidEntryPointConstants.ANDROIDXFRAGMENTCLASS);
		SootClass v4fragmentClass = Scene.v().getSootClassUnsafe(AndroidEntryPointConstants.SUPPORTFRAGMENTCLASS);
		boolean isFragment = xfragmentClass != null && Scene.v().getFastHierarchy().canStoreType(callbackHandler.getType(), xfragmentClass.getType());
		isFragment |= v4fragmentClass != null && Scene.v().getFastHierarchy().canStoreType(callbackHandler.getType(), v4fragmentClass.getType());
		if (isFragment)
			// we cannot find constructors for these...
			return true;

		{
			SootClass curHandler = callbackHandler;
			Set<SootClass> visited = new HashSet<>();
			while (curHandler.isInnerClass()) {
				if(! visited.add(curHandler)) break;
				// Do not be overly aggressive for inner classes
				SootClass outerClass = curHandler.getOuterClass();
				if (component == outerClass)
					return true;
				curHandler = outerClass;
			}
		}

		// If the component is a subclass of the callbackHandler
		if(Scene.v().getFastHierarchy().canStoreClass(component, callbackHandler) && component.isConcrete())
			return true;

		// Is this handler class instantiated in a reachable method?
		boolean hasConstructor = false;
		for (SootMethod sm : callbackHandler.getMethods()) {
			if (sm.isConstructor()) {
				if (reachableMethods.contains(sm)) {
					hasConstructor = true;
					break;
				}
			}
		}
		return hasConstructor;
	}

	@Override
	public boolean accepts(SootClass component, SootMethod callback) {
		// No filtering here
		return true;
	}

	@Override
	public void reset() {
		// nothing to do here
	}

}
