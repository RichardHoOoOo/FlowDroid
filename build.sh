rm ../soot-infoflow-classes-pre.jar
rm ../soot-infoflow-android-classes-pre.jar
rm ../soot-infoflow-summaries-classes-pre.jar
rm ../soot-infoflow-classes.jar
rm ../soot-infoflow-android-classes.jar
rm ../soot-infoflow-summaries-classes.jar

rm soot-infoflow-summaries/summariesManual/android.content.Intent.xml
rm soot-infoflow-summaries/summariesManual/android.os.BaseBundle.xml
rm soot-infoflow-summaries/summariesManual/android.os.Bundle.xml
rm soot-infoflow-summaries/summariesManual/android.os.PersistableBundle.xml
cp intent-classes-org/android.content.Intent.xml soot-infoflow-summaries/summariesManual
cp intent-classes-org/android.os.BaseBundle.xml soot-infoflow-summaries/summariesManual
cp intent-classes-org/android.os.Bundle.xml soot-infoflow-summaries/summariesManual
cp intent-classes-org/android.os.PersistableBundle.xml soot-infoflow-summaries/summariesManual
mvn -DskipTests install
cp soot-infoflow/target/soot-infoflow-classes.jar ../
cp soot-infoflow-android/target/soot-infoflow-android-classes.jar ../
cp soot-infoflow-summaries/target/soot-infoflow-summaries-classes.jar ../
mv ../soot-infoflow-classes.jar ../soot-infoflow-classes-pre.jar
mv ../soot-infoflow-android-classes.jar ../soot-infoflow-android-classes-pre.jar
mv ../soot-infoflow-summaries-classes.jar ../soot-infoflow-summaries-classes-pre.jar

rm soot-infoflow-summaries/summariesManual/android.content.Intent.xml
rm soot-infoflow-summaries/summariesManual/android.os.BaseBundle.xml
rm soot-infoflow-summaries/summariesManual/android.os.Bundle.xml
rm soot-infoflow-summaries/summariesManual/android.os.PersistableBundle.xml
cp intent-classes-revised/android.content.Intent.xml soot-infoflow-summaries/summariesManual
cp intent-classes-revised/android.os.BaseBundle.xml soot-infoflow-summaries/summariesManual
cp intent-classes-revised/android.os.Bundle.xml soot-infoflow-summaries/summariesManual
cp intent-classes-revised/android.os.PersistableBundle.xml soot-infoflow-summaries/summariesManual
mvn -DskipTests install
cp soot-infoflow/target/soot-infoflow-classes.jar ../
cp soot-infoflow-android/target/soot-infoflow-android-classes.jar ../
cp soot-infoflow-summaries/target/soot-infoflow-summaries-classes.jar ../

rm ../AndroidCallbacks.txt
cp soot-infoflow-android/AndroidCallbacks.txt ../