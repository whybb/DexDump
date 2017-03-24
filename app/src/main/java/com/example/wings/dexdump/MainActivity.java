package com.example.wings.dexdump;

import android.app.Activity;
import android.support.v7.app.AppCompatActivity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.DataOutputStream;

public class MainActivity extends AppCompatActivity {


    private EditText et;
    private TextView tv;
    private Button btn;
    @Override
    protected void onCreate(Bundle savedInstanceState)
    {

        Log.i("TAG", " the MainActivity" );
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        upgradeRootPermission(getPackageCodePath());//get the root permission
        // Example of a call to a native method
        //TextView tv = (TextView) findViewById(R.id.sample_text);
        // tv.setText(stringFromJNI());
        // Log.i("show", "native:"+stringFromJNI());

        btn = (Button) findViewById(R.id.button);
        et=(EditText)findViewById(R.id.editText);


        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v)
            {
                Intent intent =new Intent(MainActivity.this,DumpActivity.class);
                Log.i("TAG", et.getText() + "");
                String PakageName =et.getText().toString();

                //用Bundle携带数据
                Bundle bundle=new Bundle();
                //传递name参数为tinyphp
                bundle.putString("name",PakageName);
                intent.putExtras(bundle);

                //System.out.print("PakageName:"+PakageName);
                //Log.i("jw", "apkpath:"+PakageName);
                Log.i("TAG", "the pakage name is:"+PakageName);

                startActivity(intent);
            }
        });

    }
    /**
     * 应用程序运行命令获取 Root权限，设备必须已破解(获得ROOT权限)
     *
     * @return 应用程序是/否获取Root权限
     */
    public static boolean upgradeRootPermission(String pkgCodePath) {
        Process process = null;
        DataOutputStream os = null;
        try {
            String cmd="chmod 777 " + pkgCodePath;
            process = Runtime.getRuntime().exec("su"); //切换到root帐号
            os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(cmd + "\n");
            os.writeBytes("exit\n");
            os.flush();
            process.waitFor();
        } catch (Exception e) {
            return false;
        } finally {
            try {
                if (os != null) {
                    os.close();
                }
                process.destroy();
            } catch (Exception e) {
            }
        }
        return true;
    }
    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    //public static native String stringFromJNI();

    // Used to load the 'native-lib' library on application startup.
    /*static {
        System.loadLibrary("native-lib");
    }*/
}
