package com.example.wings.dexdump;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

public class DumpActivity extends AppCompatActivity
{

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dump);
        Log.i("TAG", " the dump Activity" );
        //新页面接收数据
        Bundle bundle = this.getIntent().getExtras();
        //接收name值
        String name = bundle.getString("name");
        Log.i("TAG","获取到的name值为:"+name);

        Log.i("show", "native:"+NativeTool.stringFromJNI());

        int answer= NativeTool.Dump(name);
        Log.i("TAG","come back from c++ native:"+answer);

        int answer2= NativeTool.DumpDex(name);
        Log.i("TAG","come back from c native:"+answer2);
    }
}
