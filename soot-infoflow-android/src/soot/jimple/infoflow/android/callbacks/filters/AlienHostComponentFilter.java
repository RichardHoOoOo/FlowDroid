package soot.jimple.infoflow.android.callbacks.filters;

import java.util.Set;
import java.util.HashSet;
import java.util.List;

import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.jimple.infoflow.android.entryPointCreators.AndroidEntryPointConstants;
import soot.jimple.infoflow.android.callbacks.AbstractCallbackAnalyzer;

/**
 * A callback filter that disallows inner classes from being used in other host
 * components than the outer class. If a class is a component on its own, it may
 * not be used as a callback handler in some other component.
 * 
 * Note that the rules in this filter are heuristics. They are valid for
 * sensible applications, but may be disregarded on purpose by a malicious
 * developer.
 * 
 * @author Steven Arzt
 *
 */
public class AlienHostComponentFilter extends AbstractCallbackFilter {

	private SootClass activityClass;
	private SootClass xfragmentClass;
	private SootClass v4fragmentClass;
	private Set<SootClass> components;

	/**
	 * Creates a new instance of the {@link AlienHostComponentFilter} class
	 * 
	 * @param components The set of components in the Android app
	 */
	public AlienHostComponentFilter(Set<SootClass> components) {
		this.components = new HashSet<>();
		this.components.addAll(components);
	}

	public void addComponent(SootClass component) {
		this.components.add(component);
	}

	@Override
	public boolean accepts(SootClass component, SootClass callbackHandler) {
		// Some sanity checks
		if (callbackHandler == null || component == null)
			return false;

		// If we haven't been initialized before, we do that now
		if (activityClass == null || xfragmentClass == null || v4fragmentClass == null)
			reset();

		// If the callback class is a fragment, but the hosting component is not
		// an activity, this association must be wrong.
		// if (xfragmentClass != null && activityClass != null) {
		// 	if (Scene.v().getOrMakeFastHierarchy().canStoreType(callbackHandler.getType(),
		// 			this.xfragmentClass.getType()))
		// 		if (!Scene.v().getOrMakeFastHierarchy().canStoreType(component.getType(), this.activityClass.getType()))
		// 			return false;
		// }
		// if (v4fragmentClass != null && activityClass != null) {
		// 	if (Scene.v().getOrMakeFastHierarchy().canStoreType(callbackHandler.getType(),
		// 			this.v4fragmentClass.getType()))
		// 		if (!Scene.v().getOrMakeFastHierarchy().canStoreType(component.getType(), this.activityClass.getType()))
		// 			return false;
		// }

		// If the callback handler is an inner class, we only accept it if its
		// outer class matches the component
		{
			SootClass curHandler = callbackHandler;
			Set<SootClass> visited = new HashSet<>();
			while (curHandler.isInnerClass()) {
				if(! visited.add(curHandler)) break;
				// In cases like a fragment is an inner class of an activity, if we do not have the following check, 
				// the outer classes will finally become the activity, which is not the child of the inner fragment.
				// false will be returned
				if(Scene.v().getOrMakeFastHierarchy().canStoreType(component.getType(), curHandler.getType())) break;
				SootClass outerClass = curHandler.getOuterClass();
				if (components.contains(outerClass) && !Scene.v().getOrMakeFastHierarchy()
						.canStoreType(component.getType(), outerClass.getType())) {
					return false;
				}
				curHandler = outerClass;
			}
		}

		{
			// Use string analysis to check outer classes again
			List<SootClass> outerClasses = AbstractCallbackAnalyzer.getAllOuterClasses(callbackHandler);
			for(SootClass outerCls: outerClasses) {
				if(Scene.v().getOrMakeFastHierarchy().canStoreType(component.getType(), outerCls.getType())) break;
				if (components.contains(outerCls) && ! Scene.v().getOrMakeFastHierarchy().canStoreType(component.getType(), outerCls.getType())) return false;
			}
		}

		// If the callback handler is a component on its own, we do not accept
		// it to be called in the lifecycle of any other components.
		if (components.contains(callbackHandler) && callbackHandler != component) {
			return false;
		}

		// If the callback class only has constructors that require references
		// to other components, it is not meant to be used by the current
		// component.
		for (SootMethod cons : callbackHandler.getMethods()) {
			if (cons.isConstructor() && !cons.isPrivate()) {
				boolean isConstructorUsable = true;

				// Check if we have at least one other component in the parameter
				// list
				for (int i = 0; i < cons.getParameterCount(); i++) {
					Type paramType = cons.getParameterType(i);
					if (paramType != component.getType() && paramType instanceof RefType) {
						if (components.contains(((RefType) paramType).getSootClass())) {
							isConstructorUsable = false;
							break;
						}
					}
				}

				// Do we have a usable constructor?
				if (!isConstructorUsable) {
					return false;
				}
			}
		}

		return true;
	}

	@Override
	public void reset() {
		this.activityClass = Scene.v().getSootClassUnsafe(AndroidEntryPointConstants.ACTIVITYCLASS);
		this.xfragmentClass = Scene.v().getSootClassUnsafe(AndroidEntryPointConstants.ANDROIDXFRAGMENTCLASS);
		this.v4fragmentClass = Scene.v().getSootClassUnsafe(AndroidEntryPointConstants.SUPPORTFRAGMENTCLASS);
	}

	@Override
	public boolean accepts(SootClass component, SootMethod callback) {
		// We do not implement this method
		return true;
	}

}
