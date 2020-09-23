package org.apache.cordova.posPlugin;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaInterface;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.dspread.xpos.EmvAppTag;
import com.dspread.xpos.EmvCapkTag;
import com.dspread.xpos.QPOSService;
import com.dspread.xpos.QPOSService.CommunicationMode;
import com.dspread.xpos.QPOSService.Display;
import com.dspread.xpos.QPOSService.DoTradeResult;
import com.dspread.xpos.QPOSService.EMVDataOperation;
import com.dspread.xpos.QPOSService.EmvOption;
import com.dspread.xpos.QPOSService.Error;
import com.dspread.xpos.QPOSService.QPOSServiceListener;
import com.dspread.xpos.QPOSService.TransactionResult;
import com.dspread.xpos.QPOSService.TransactionType;
import com.dspread.xpos.QPOSService.UpdateInformationResult;
import com.pos.demoui.DUKPK2009_CBC;
import com.printer.PrinterInstance;
import com.printer.bluetooth.BluetoothPort;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.provider.ContactsContract.AggregationExceptions;
import android.support.v4.app.ActivityCompat;
import android.webkit.JavascriptInterface;
import android.widget.Toast;

/**
 * This class echoes a string called from JavaScript.
 */
public class dspread_pos_plugin extends CordovaPlugin {
	private MyPosListener listener;
	private QPOSService pos;
	private BluetoothAdapter mAdapter; 
	private String sdkVersion;
	private String blueToothAddress;
	private List<BluetoothDevice> listDevice;
	private String terminalTime = new SimpleDateFormat("yyyyMMddHHmmss").format(Calendar.getInstance().getTime());
	private String currencyCode = "156";
	private TransactionType transactionType = TransactionType.GOODS;
	ArrayList<String> list=new ArrayList<String>();
	private String amount = "";
	private String cashbackAmount = "";
	private List<Map<String, ?>> data = new ArrayList<Map<String, ?>>();
	private static final int PROGRESS_UP = 1001;
	private PrinterInstance mPrinter;
	private String printerAddress;
	private String printerName;
	private Hashtable<String, String> pairedDevice;
	private Activity activity;
    private CordovaWebView webView;
    private boolean posFlag=false;

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    	
        return super.execute(action, args, callbackContext);
    }
    
    @Override
    public boolean execute(String action, CordovaArgs args, CallbackContext callbackContext) throws JSONException {
    	if(action.equals("scanQPos2Mode")) {
        	boolean a=pos.scanQPos2Mode(activity, 10);
        	Toast.makeText(cordova.getActivity(), "scan success", Toast.LENGTH_LONG).show();
        }else if(action.equals("keyExchange")){
    		String data = args.getString(0);
    		String key = args.getString(1);
			byte[] result = DUKPK2009_CBC.TriDesDecryptionECB(QPOSUtil.HexStringToByteArray(key),QPOSUtil.HexStringToByteArray(data));
			String keyResult = QPOSUtil.byteArray2Hex(result);
			TRACE.i("ddd = " + keyResult);
//			callbackJs(keyResult,"getKeyResult");
		}else if(action.equals("connectBluetoothDevice")){//connect
        	boolean isAutoConnect=args.getBoolean(0);
        	String address=args.getString(1);
        	int i=address.indexOf("(");
        	int e=address.indexOf(")");
        	String mac=address.substring(i+1,e);
        	TRACE.d("address==="+mac);
        	pos.connectBluetoothDevice(isAutoConnect, 20, mac);
        }else if(action.equals("doTrade")){//start to do a trade
        	int timeout=args.getInt(0);
        	pos.doTrade(timeout);
        }else if(action.equals("getDeviceList")){//get all scaned devices
        	TRACE.w("getDeviceList===");
        	posFlag=true;
        	listDevice=pos.getDeviceList();//can get all scaned device
        	TRACE.w("getDeviceList size==="+listDevice.size());
        /*	for (BluetoothDevice dev : listDevice) {
        		Map<String, Object> itm = new HashMap<String, Object>();
        		itm.put("TITLE", dev.getName() + "(" + dev.getAddress() + ")");
    			itm.put("ADDRESS", dev.getAddress());
    			data.add(itm);
//    			blueToothAddress=dev.getAddress();
        	}*/
        	String[] macAddress=new String[listDevice.size()];
        	String devices="";
        	for(int i=0;i<listDevice.size();i++){
        		macAddress[i]=listDevice.get(i).getName()+"("+listDevice.get(i).getAddress()+"),";
        		if(i==list.size()-1){
        			macAddress[i]=listDevice.get(i).getName()+"("+listDevice.get(i).getAddress()+")";
        		}
        		devices+=macAddress[i];
        	}
        	TRACE.w("get devi=="+devices);
        	callback(devices);
        }else if(action.equals("stopScanQPos2Mode")){//stop scan bluetooth
        	pos.stopScanQPos2Mode();
        }else if(action.equals("disconnectBT")){//discooect bluetooth
        	pos.disconnectBT();
        }else if(action.equals("getQposInfo")){//get the pos info
        	pos.getQposInfo();
        }else if(action.equals("getQposId")){//get the pos id
        	pos.getQposId(20);
        }else if(action.equals("updateIPEK")){//update the ipek key
        	String ipekGroup=args.getString(0);
        	String trackksn=args.getString(1);
        	String trackipek=args.getString(2);
        	String trackipekCheckvalue=args.getString(3);
        	String emvksn=args.getString(4);
        	String emvipek=args.getString(5);
        	String emvipekCheckvalue=args.getString(6);
        	String pinksn=args.getString(7);
        	String pinipek=args.getString(8);
        	String pinipekCheckvalue=args.getString(9);
//        	pos.doUpdateIPEKOperation("00", "09117081600001E00001", "413DF85BD9D9A7C34EDDB2D2B5CA0C0F", "6A52E41A7F91C9F5", "09117081600001E00001", "413DF85BD9D9A7C34EDDB2D2B5CA0C0F", "6A52E41A7F91C9F5", "09117081600001E00001", "413DF85BD9D9A7C34EDDB2D2B5CA0C0F", "6A52E41A7F91C9F5");
        	pos.doUpdateIPEKOperation(ipekGroup, trackksn, trackipek, trackipekCheckvalue, emvksn, emvipek, emvipekCheckvalue, pinksn, pinipek, pinipekCheckvalue);
        }else if(action.equals("updateEmvApp")){//update the emv app config
        	list.add(EmvAppTag.Terminal_Default_Transaction_Qualifiers+"36C04000");
			list.add(EmvAppTag.Contactless_CVM_Required_limit+"000000060000");
			list.add(EmvAppTag.terminal_contactless_transaction_limit+"000000060000");
        	pos.updateEmvAPP(EMVDataOperation.update,list);
        }else if(action.equals("updateEmvCAPK")){//update the emv capk config
        	list.add(EmvCapkTag.RID+"A000000004");
			list.add(EmvCapkTag.Public_Key_Index+"F1");
			list.add(EmvCapkTag.Public_Key_Module+"A0DCF4BDE19C3546B4B6F0414D174DDE294AABBB828C5A834D73AAE27C99B0B053A90278007239B6459FF0BBCD7B4B9C6C50AC02CE91368DA1BD21AAEADBC65347337D89B68F5C99A09D05BE02DD1F8C5BA20E2F13FB2A27C41D3F85CAD5CF6668E75851EC66EDBF98851FD4E42C44C1D59F5984703B27D5B9F21B8FA0D93279FBBF69E090642909C9EA27F898959541AA6757F5F624104F6E1D3A9532F2A6E51515AEAD1B43B3D7835088A2FAFA7BE7");
			list.add(EmvCapkTag.Public_Key_CheckValue+"D8E68DA167AB5A85D8C3D55ECB9B0517A1A5B4BB");
			list.add(EmvCapkTag.Pk_exponent+"03");
        	pos.updateEmvCAPK(EMVDataOperation.update, list);
        }else if(action.equals("setMasterKey")){//set the masterkey
        	String key=args.getString(0);
        	String checkValue=args.getString(1);
        	pos.setMasterKey(key,checkValue);
        }else if(action.equals("updatePosFirmware")){//update pos firmware
        	byte[] data=readLine("upgrader.asc");//upgrader.asc place in the assets folder
        	pos.updatePosFirmware(data, blueToothAddress);//deviceAddress is BluetoothDevice address
        	UpdateThread updateThread = new UpdateThread();
			updateThread.start();
        }else if(action.equals("connectBTPrinter")){//connect the printer
        	mPrinter = new BluetoothPort().btConnnect(cordova.getActivity(), printerAddress, mAdapter, updata_handler);
        }else if(action.equals("disconnectBTPrinter")){//disconnect the printer
        	mPrinter.closeConnection();
        }else if(action.equals("printText")){
        	String content=args.getString(0);
        	mPrinter.init();//init the printer
			mPrinter.printText(content);//print the text
			mPrinter.setPrinter(1, 2);//PRINT_AND_WAKE_PAPER_BY_LINE
        }
        return true;
    }
    
    @JavascriptInterface
    public void callback(String mac) {
    	TRACE.d("callback js =="+mac);
    	if(posFlag){
    		callJS("addDevices('"+mac+"')");
    	}else{
    		callJS("posresult('"+mac+"')");
    	}
    	posFlag=false;
    }

	@JavascriptInterface
	public void callbackJs(String mac,String id) {
		TRACE.d("callback js =="+mac);
		callJS(id+"('"+mac+"')");
	}

    //call js file
    private void callJS(final String js) {
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                webView.loadUrl("javascript:" + js);
            }
        });
    }
    
    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    	// TODO Auto-generated method stub
    	super.initialize(cordova, webView);
    	this.activity=cordova.getActivity();
    	this.webView=webView;
    	open(CommunicationMode.BLUETOOTH);//initial the open mode
//    	requestPer();
    }
    
    //initial the pos
    private void open(CommunicationMode mode) {
		TRACE.d("open");
		listener = new MyPosListener();
		pos = QPOSService.getInstance(mode);
		if (pos == null) {
			TRACE.d("CommunicationMode unknow");
			return;
		}
		pos.setConext(cordova.getActivity());
		Handler handler = new Handler(Looper.myLooper());
		pos.initListener(handler, listener);
//		sdkVersion = pos.getSdkVersion();
//		TRACE.i("sdkVersion:"+sdkVersion);
		mAdapter=BluetoothAdapter.getDefaultAdapter();;
		pairedDevice=BluetoothPort.getPairedDevice(mAdapter);
//		if(pairedDevice!=null){
//			printerAddress=pairedDevice.get("deviceAddress");//get the S85 printer address and name
//			printerName=pairedDevice.get("deviceName");
//		}else{
//			Toast.makeText(activity, "please first to paired the printer", Toast.LENGTH_LONG).show();
//		}
	}
    
  /*  private void requestPer(){
    		if (Build.VERSION.SDK_INT >= 23) {
    	        if(!cordova.hasPermission("android.permission.ACCESS_FINE_LOCATION")){
    	        	cordova.requestPermission(this, 100, "android.permission.ACCESS_FINE_LOCATION");
    	        	cordova.requestPermission(this, 101, "android.permission.ACCESS_COARSE_LOCATION");
    	        	TRACE.d( "retuest the permission");
    	        }else{
    	        	TRACE.d( "has the permission");
    	        }
    	    }
    }*/
    
    private void sendMsg(int what) {
		Message msg = new Message();
		msg.what = what;
		mHandler.sendMessage(msg);
	}
    
    private Handler mHandler=new Handler(){
    	public void handleMessage(Message msg) {
    		switch (msg.what) {
			case 8003:
				Hashtable<String, String> h =  pos.getNFCBatchData();
				TRACE.w("nfc batchdata: "+h);
				String content = "\nNFCbatchData: "+h.get("tlv");
				break;

			default:
				break;
			}
    	};
    };
    
    //read the buffer
    private byte[] readLine(String Filename) {

		String str = "";
		ByteArrayOutputStream buffer = new ByteArrayOutputStream(0);
		try {
			android.content.ContextWrapper contextWrapper = new ContextWrapper(cordova.getActivity());
			AssetManager assetManager = contextWrapper.getAssets();
			InputStream inputStream = assetManager.open(Filename);
			// BufferedReader br = new BufferedReader(new
			// InputStreamReader(inputStream));
			// str = br.readLine();
			int b = inputStream.read();
			while (b != -1) {
				buffer.write((byte) b);
				b = inputStream.read();
			}
			TRACE.d("-----------------------");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return buffer.toByteArray();
	}
    
    class UpdateThread extends Thread {
		public void run() {
			
			while (true) {
				try {
					Thread.sleep(10);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				int progress = pos.getUpdateProgress();
				if (progress < 100) {
					Message msg = updata_handler.obtainMessage();
					msg.what = PROGRESS_UP;
					msg.obj = progress;
					msg.sendToTarget();
					continue;
				}
				Message msg = updata_handler.obtainMessage();
				msg.what = PROGRESS_UP;
				msg.obj = "update success";
				msg.sendToTarget();
				break;
			}
		};
	};
	
	private Handler updata_handler = new Handler() {
		public void handleMessage(Message msg) {
			switch (msg.what) {
			case PROGRESS_UP://update the firmware
				TRACE.i(msg.obj.toString() + "%");
				break;
			case 101://the callback of the connect the printer success
				Toast.makeText(cordova.getActivity(), "connect the printer success", Toast.LENGTH_LONG).show();
				break;
			default:
				break;
			}
		};
	};
   
	//our sdk api callback(success or fail)
    class MyPosListener implements QPOSServiceListener{

		@Override
		public void getMifareCardVersion(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void getMifareFastReadData(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void getMifareReadData(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onAddKey(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onBluetoothBoardStateResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onBluetoothBondFailed() {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onBluetoothBondTimeout() {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onBluetoothBonded() {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onBluetoothBonding() {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onCbcMacResult(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onConfirmAmountResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onDeviceFound(BluetoothDevice arg0) {
			if(arg0!=null){
				String address=arg0.getAddress();
				String name=arg0.getName();
				String mac = name+" "+address;
				TRACE.i("scaned the device:\n"+name+"("+address+")");
				callbackJs(mac,"addrow");
			}
		}

		@Override
		public void onDoTradeResult(DoTradeResult arg0, Hashtable<String, String> arg1) {
			if (arg0 == DoTradeResult.NONE) {
				TRACE.d("no_card_detected");
			} else if (arg0 == DoTradeResult.ICC) {
				TRACE.d("icc_card_inserted");
				TRACE.d("EMV ICC Start");
				pos.doEmvApp(EmvOption.START);//do the icc card trade
			} else if (arg0 == DoTradeResult.NOT_ICC) {
				TRACE.d("card_inserted(NOT_ICC)");
			} else if (arg0 == DoTradeResult.BAD_SWIPE) {
				TRACE.d("bad_swipe");
			} else if (arg0 == DoTradeResult.MCR) {//
				String content ="swipe card:";
				String formatID = arg1.get("formatID");
				if (formatID.equals("31") || formatID.equals("40") || formatID.equals("37") || formatID.equals("17") || formatID.equals("11") || formatID.equals("10")) {
					String maskedPAN = arg1.get("maskedPAN");
					String expiryDate = arg1.get("expiryDate");
					String cardHolderName = arg1.get("cardholderName");
					String serviceCode = arg1.get("serviceCode");
					String trackblock = arg1.get("trackblock");
					String psamId = arg1.get("psamId");
					String posId = arg1.get("posId");
					String pinblock = arg1.get("pinblock");
					String macblock = arg1.get("macblock");
					String activateCode = arg1.get("activateCode");
					String trackRandomNumber = arg1.get("trackRandomNumber");

					content += "format_id" + " " + formatID + "\n";
					content += "masked_pan" + " " + maskedPAN + "\n";
					content += "expiry_date" + " " + expiryDate + "\n";
					content += "cardholder_name" + " " + cardHolderName + "\n";

					content += "service_code"+ " " + serviceCode + "\n";
					content += "trackblock: " + trackblock + "\n";
					content += "psamId: " + psamId + "\n";
					content += "posId: " + posId + "\n";
					content += "pinBlock" + " " + pinblock + "\n";
					content += "macblock: " + macblock + "\n";
					content += "activateCode: " + activateCode + "\n";
					content += "trackRandomNumber: " + trackRandomNumber + "\n";
				} else if (formatID.equals("FF")) {
					String type = arg1.get("type");
					String encTrack1 = arg1.get("encTrack1");
					String encTrack2 = arg1.get("encTrack2");
					String encTrack3 = arg1.get("encTrack3");
					content += "cardType:" + " " + type + "\n";
					content += "track_1:" + " " + encTrack1 + "\n";
					content += "track_2:" + " " + encTrack2 + "\n";
					content += "track_3:" + " " + encTrack3 + "\n";
				} else {
					String orderID=arg1.get("orderId");
					String maskedPAN = arg1.get("maskedPAN");
					String expiryDate = arg1.get("expiryDate");
					String cardHolderName = arg1.get("cardholderName");
//					String ksn = arg1.get("ksn");
					String serviceCode = arg1.get("serviceCode");
					String track1Length = arg1.get("track1Length");
					String track2Length = arg1.get("track2Length");
					String track3Length = arg1.get("track3Length");
					String encTracks = arg1.get("encTracks");
					String encTrack1 = arg1.get("encTrack1");
					String encTrack2 = arg1.get("encTrack2");
					String encTrack3 = arg1.get("encTrack3");
					String partialTrack = arg1.get("partialTrack");
					// TODO
					String pinKsn = arg1.get("pinKsn");
					String trackksn = arg1.get("trackksn");
					String pinBlock = arg1.get("pinBlock");
					String encPAN = arg1.get("encPAN");
					String trackRandomNumber = arg1.get("trackRandomNumber");
					String pinRandomNumber = arg1.get("pinRandomNumber");
					if(orderID!=null&&!"".equals(orderID)){
						content+="orderID:"+orderID;
					}
					content += "formatID" + " " + formatID + ",";
					content += "maskedPAN" + " " + maskedPAN + ",";
					content += "expiryDate" + " " + expiryDate + ",";
					content += "cardHolderName" + " " + cardHolderName + ",";
//					content += getString(R.string.ksn) + " " + ksn + ",";
					content += "pinKsn" + " " + pinKsn + ",";
					content += "trackksn" + " " + trackksn + ",";
					content += "serviceCode" + " " + serviceCode + ",";
					content += "track1Length" + " " + track1Length + ",";
					content += "track2Length" + " " + track2Length + ",";
					content += "track3Length" + " " + track3Length + ",";
					content += "encTracks" + " " + encTracks + ",";
					content += "encTrack1" + " " + encTrack1 + ",";
					content += "encTrack2" + " " + encTrack2 + ",";
					content += "encTrack3" + " " + encTrack3 + ",";
					content += "partialTrack"+ " " + partialTrack + ",";
					content += "pinBlock" + " " + pinBlock + ",";
					content += "encPAN: " + encPAN + ",";
					content += "trackRandomNumber: " + trackRandomNumber + ",";
					content += "pinRandomNumber:" + " " + pinRandomNumber + "";
					callback(content);
				}
				TRACE.d("=====:" + content);
			} else if ((arg0 == DoTradeResult.NFC_ONLINE) || (arg0 == DoTradeResult.NFC_OFFLINE)) {
				TRACE.d(arg0+", arg1: " + arg1);
//				nfcLog=arg1.get("nfcLog");
				String content = "tap_card";
				String formatID = arg1.get("formatID");
				if (formatID.equals("31") || formatID.equals("40")
						|| formatID.equals("37") || formatID.equals("17")
						|| formatID.equals("11") || formatID.equals("10")) {
					String maskedPAN = arg1.get("maskedPAN");
					String expiryDate = arg1.get("expiryDate");
					String cardHolderName = arg1.get("cardholderName");
					String serviceCode = arg1.get("serviceCode");
					String trackblock = arg1.get("trackblock");
					String psamId = arg1.get("psamId");
					String posId = arg1.get("posId");
					String pinblock = arg1.get("pinblock");
					String macblock = arg1.get("macblock");
					String activateCode = arg1.get("activateCode");
					String trackRandomNumber = arg1
							.get("trackRandomNumber");

					content += "formatID" + " " + formatID
							+ "\n";
					content += "maskedPAN" + " " + maskedPAN
							+ "\n";
					content += "expiryDate" + " "
							+ expiryDate + "\n";
					content += "cardHolderName" + " "
							+ cardHolderName + "\n";

					content += "serviceCode" + " "
							+ serviceCode + "\n";
					content += "trackblock: " + trackblock + "\n";
					content += "psamId: " + psamId + "\n";
					content += "posId: " + posId + "\n";
					content += "pinblock" + " " + pinblock
							+ "\n";
					content += "macblock: " + macblock + "\n";
					content += "activateCode: " + activateCode + "\n";
					content += "trackRandomNumber: " + trackRandomNumber + "\n";
				} else {

					String maskedPAN = arg1.get("maskedPAN");
					String expiryDate = arg1.get("expiryDate");
					String cardHolderName = arg1.get("cardholderName");
//					String ksn = arg1.get("ksn");
					String serviceCode = arg1.get("serviceCode");
					String track1Length = arg1.get("track1Length");
					String track2Length = arg1.get("track2Length");
					String track3Length = arg1.get("track3Length");
					String encTracks = arg1.get("encTracks");
					String encTrack1 = arg1.get("encTrack1");
					String encTrack2 = arg1.get("encTrack2");
					String encTrack3 = arg1.get("encTrack3");
					String partialTrack = arg1.get("partialTrack");
					// TODO
					String pinKsn = arg1.get("pinKsn");
					String trackksn = arg1.get("trackksn");
					String pinBlock = arg1.get("pinBlock");
					String encPAN = arg1.get("encPAN");
					String trackRandomNumber = arg1
							.get("trackRandomNumber");
					String pinRandomNumber = arg1.get("pinRandomNumber");

					content +="formatID" + " " + formatID
							+ ",";
					content += "maskedPAN" + " " + maskedPAN
							+ ",";
					content += "expiryDate" + " "
							+ expiryDate + ",";
					content += "cardHolderName"+ " "
							+ cardHolderName + ",";
//					content += getString(R.string.ksn) + " " + ksn + ",";
					content += "pinKsn" + " " + pinKsn + ",";
					content += "trackksn" + " " + trackksn
							+ ",";
					content += "trackksn" + " "
							+ serviceCode + ",";
					content += "track1Length" + " "
							+ track1Length + ",";
					content += "track2Length" + " "
							+ track2Length + ",";
					content += "track3Length" + " "
							+ track3Length + ",";
					content += "encTracks" + " "
							+ encTracks + ",";
					content += "encTracks1" + " "
							+ encTrack1 + ",";
					content += "encTracks2" + " "
							+ encTrack2 + ",";
					content += "encTracks3"+ " "
							+ encTrack3 + ",";
					content += "partialTrack" + " "
							+ partialTrack + ",";
					content += "pinBlock"+ " " + pinBlock
							+ ",";
					content += "encPAN: " + encPAN + ",";
					content += "trackRandomNumber: " + trackRandomNumber + ",";
					content += "pinRandomNumber:" + " " + pinRandomNumber
							+ ",";
				}
				TRACE.w(arg0+": "+content);
//				sendMsg(8003);
				Hashtable<String, String> h =  pos.getNFCBatchData();
				TRACE.w("nfc batchdata: "+h);
				content += "NFCbatchData: "+h.get("tlv");
				callback(content);
			} else if ((arg0 == DoTradeResult.NFC_DECLINED) ) {
				TRACE.d("transaction_declined");
			}else if (arg0 == DoTradeResult.NO_RESPONSE) {
				TRACE.d("card_no_response");
			}
		}

		@Override
		public void onEmvICCExceptionData(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onEncryptData(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onError(Error arg0) {
			TRACE.d("onError");
			if (arg0 == Error.CMD_NOT_AVAILABLE) {
				TRACE.d("command_not_available");
			} else if (arg0 == Error.TIMEOUT) {
				TRACE.d("device_no_response");
			} else if (arg0 == Error.DEVICE_RESET) {
				TRACE.d("device_reset");
			} else if (arg0 == Error.UNKNOWN) {
				TRACE.d("unknown_error");
			} else if (arg0 == Error.DEVICE_BUSY) {
				TRACE.d("device_busy");
			} else if (arg0 == Error.INPUT_OUT_OF_RANGE) {
				TRACE.d("out_of_range");
			} else if (arg0 == Error.INPUT_INVALID_FORMAT) {
				TRACE.d("invalid_format");
			} else if (arg0 == Error.INPUT_ZERO_VALUES) {
				TRACE.d("zero_values");
			} else if (arg0 == Error.INPUT_INVALID) {
				TRACE.d("input_invalid");
			} else if (arg0 == Error.CASHBACK_NOT_SUPPORTED) {
				TRACE.d("CASHBACK_NOT_SUPPORTED");
			} else if (arg0 == Error.CRC_ERROR) {
				TRACE.d("crc_error");
			} else if (arg0 == Error.COMM_ERROR) {
				TRACE.d("comm_error");
			} else if (arg0 == Error.MAC_ERROR) {
				TRACE.d("mac_error");
			} else if (arg0 == Error.CMD_TIMEOUT) {
				TRACE.d("CMD_TIMEOUT");
			}
		}

		@Override
		public void onFinishMifareCardResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onGetCardNoResult(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onGetInputAmountResult(boolean arg0, String arg1) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onGetPosComm(int arg0, String arg1, String arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onGetShutDownTime(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onGetSleepModeTime(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onLcdShowCustomDisplay(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onOperateMifareCardResult(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onPinKey_TDES_Result(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onQposDoGetTradeLog(String arg0, String arg1) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onQposDoGetTradeLogNum(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onQposDoSetRsaPublicKey(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onQposDoTradeLog(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onQposGenerateSessionKeysResult(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onQposIdResult(Hashtable<String, String> arg0) {
			if(arg0!=null){
				String posId = arg0.get("posId") == null ? "" : arg0
						.get("posId");
				String csn = arg0.get("csn") == null ? "" : arg0
						.get("csn");
				String psamId=arg0.get("psamId") == null ? "" : arg0
						.get("psamId");
				
				String content = "";
				content += "posId" + posId + "\n";
				content += "csn: " + csn + "\n";
				content += "conn: " + pos.getBluetoothState() + "\n";
				content += "psamId: " + psamId + "\n";
				callback(content);
			}
		}

		@Override
		public void onQposInfoResult(Hashtable<String, String> arg0) {
			TRACE.d("onQposInfoResult"+arg0);
			String isSupportedTrack1 = arg0.get("isSupportedTrack1") == null ? "" : arg0.get("isSupportedTrack1");
			String isSupportedTrack2 = arg0.get("isSupportedTrack2") == null ? "" : arg0.get("isSupportedTrack2");
			String isSupportedTrack3 = arg0.get("isSupportedTrack3") == null ? "" : arg0.get("isSupportedTrack3");
			String bootloaderVersion = arg0.get("bootloaderVersion") == null ? "" : arg0.get("bootloaderVersion");
			String firmwareVersion = arg0.get("firmwareVersion") == null ? "" : arg0.get("firmwareVersion");
			String isUsbConnected = arg0.get("isUsbConnected") == null ? "" : arg0.get("isUsbConnected");
			String isCharging = arg0.get("isCharging") == null ? "" : arg0.get("isCharging");
			String batteryLevel = arg0.get("batteryLevel") == null ? "" : arg0.get("batteryLevel");
			String batteryPercentage = arg0.get("batteryPercentage") == null ? ""
					: arg0.get("batteryPercentage");
			String hardwareVersion = arg0.get("hardwareVersion") == null ? "" : arg0.get("hardwareVersion");
			String SUB=arg0.get("SUB")== null ? "" : arg0.get("SUB");
			String content = "";
			content += "bootloader_version" + bootloaderVersion + "\n";
			content += "firmwareVersion" + firmwareVersion + "\n";
			content += "isUsbConnected" + isUsbConnected + "\n";
			content += "isCharging" + isCharging + "\n";
//			if (batteryPercentage==null || "".equals(batteryPercentage)) {
				content += "batteryLevel" + batteryLevel + "\n";
//			}else {
				content += "batteryPercentage"  + batteryPercentage + "\n";
//			}
			content += "hardwareVersion" + hardwareVersion + "\n";
			content += "SUB : " + SUB + "\n";
			content += "isSupportedTrack1" + isSupportedTrack1 + "\n";
			content += "isSupportedTrack2" + isSupportedTrack2 + "\n";
			content += "isSupportedTrack3" + isSupportedTrack3 + "\n";
			callback(content);
		}

		@Override
		public void onQposIsCardExist(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onQposKsnResult(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReadBusinessCardResult(boolean arg0, String arg1) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReadMifareCardResult(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onRequestBatchData(String arg0) {
			if(arg0!=null){
				callback(arg0);
			}else{
				callback(null);
			}
		}

		@Override
		public void onRequestCalculateMac(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onRequestDeviceScanFinished() {
			TRACE.i("scan finished");
		}

		@Override
		public void onRequestDisplay(Display arg0) {
			TRACE.d("onRequestDisplay");

			String msg = "";
			if (arg0 == Display.CLEAR_DISPLAY_MSG) {
				msg = "" ;
			} else if(arg0 == Display.MSR_DATA_READY){
				AlertDialog.Builder builder=new AlertDialog.Builder(cordova.getActivity());
				builder.setTitle("???");
				builder.setMessage("Success,Contine ready");
				builder.setPositiveButton("???", null);
				builder.show();
			}else if (arg0 == Display.PLEASE_WAIT) {
				msg = "please wait..";
			} else if (arg0 == Display.REMOVE_CARD) {
				msg = "remove card";
			} else if (arg0 == Display.TRY_ANOTHER_INTERFACE) {
				msg = "try another interface";
			} else if (arg0 == Display.PROCESSING) {
				msg = "processing...";
			} else if (arg0 == Display.INPUT_PIN_ING) {
				msg = "please input pin on pos";
			} else if (arg0 == Display.MAG_TO_ICC_TRADE) {
				msg = "please insert chip card on pos";
			}else if (arg0 == Display.CARD_REMOVED) {
				msg = "card removed";
			}
			TRACE.d(msg);
			callback(msg);
		}

		@Override
		public void onRequestFinalConfirm() {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onRequestIsServerConnected() {
			TRACE.d("onRequestIsServerConnected");
			pos.isServerConnected(true);
		}

		@Override
		public void onRequestNoQposDetected() {
			TRACE.w("onRequestNoQposDetected");
			Toast.makeText(cordova.getActivity(), "onRequestNoQposDetected", Toast.LENGTH_LONG).show();
		}

		@Override
		public void onRequestOnlineProcess(String arg0) {
			TRACE.d("onRequestOnlineProcess");
			TRACE.i("return transaction online data:"+arg0);
			Hashtable<String, String> decodeData = pos.anlysEmvIccData(arg0);
			TRACE.i("decodeData:" + decodeData);
			//go online
			String str = "5A0A6214672500000000056F5F24032307315F25031307085F2A0201565F34010182027C008407A00000033301018E0C000000000000000002031F009505088004E0009A031406179C01009F02060000000000019F03060000000000009F0702AB009F080200209F0902008C9F0D05D86004A8009F0E0500109800009F0F05D86804F8009F101307010103A02000010A010000000000CE0BCE899F1A0201569F1E0838333230314943439F21031826509F2608881E2E4151E527899F2701809F3303E0F8C89F34030203009F3501229F3602008E9F37042120A7189F4104000000015A0A6214672500000000056F5F24032307315F25031307085F2A0201565F34010182027C008407A00000033301018E0C000000000000000002031F00";
			pos.sendOnlineProcessResult("8A023030"+str);
		}

		@Override
		public void onRequestQposConnected() {
			TRACE.w("onRequestQposConnected");
//			Toast.makeText(cordova.getActivity(), "onRequestQposConnected", Toast.LENGTH_LONG).show();
			callback("onRequestQposConnected");
		}

		@Override
		public void onRequestQposDisconnected() {
			TRACE.w("onRequestQposDisconnected");
//			Toast.makeText(cordova.getActivity(), "onRequestQposDisconnected", Toast.LENGTH_LONG).show();
			callback("onRequestQposDisconnected");
		}

		@Override
		public void onRequestSelectEmvApp(ArrayList<String> arg0) {
			TRACE.d("onRequestSelectEmvApp");
			TRACE.d("pls choose App -- S??emv card config");
			String[] appNameList = new String[arg0.size()];
			for (int i = 0; i < appNameList.length; ++i) {
				TRACE.d("i=" + i + "," + arg0.get(i));
				appNameList[i] = arg0.get(i);
			}
			pos.selectEmvApp(0);//choose one emv card
//			pos.cancelSelectEmvApp();//cancel select the emv card config
		}

		@Override
		public void onRequestSetAmount() {
			//the below list represent the transaction type
//			String[] transactionTypes = new String[] {"GOODS", "SERVICES", "CASHBACK", "INQUIRY", "TRANSFER", "PAYMENT","CHANGE_PIN","REFOUND"  };
			pos.setPosDisplayAmountFlag(true);
			pos.setAmount("12", "", "156", transactionType);
			TRACE.d("onRequestSetAmount");
		}

		@Override
		public void onRequestSetPin() {
			TRACE.d("onRequestSetPin");
			String pin="";
			if (pin.length() >= 4 && pin.length() <= 12) {
				pos.sendPin(pin);
			}
		}

		@Override
		public void onRequestSignatureResult(byte[] arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onRequestTime() {
			TRACE.d("onRequestTime");
			pos.sendTime(terminalTime);
			TRACE.d("request_terminal_time:" + " " + terminalTime);
		}

		@Override
		public void onRequestTransactionLog(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onRequestTransactionResult(TransactionResult arg0) {
			TRACE.d("onRequestTransactionResult");
			if (arg0 == TransactionResult.APPROVED) {
				TRACE.d("TransactionResult.APPROVED");
				String message = "transaction_approved" + "\n" + "amount" + ": $" + amount + "\n";
				if (!cashbackAmount.equals("")) {
					message += "cashbackAmount" + ": INR" + cashbackAmount;
				}
			} else if (arg0 == TransactionResult.TERMINATED) {
				TRACE.d("TERMINATED");
			} else if (arg0 == TransactionResult.DECLINED) {
				TRACE.d("DECLINED");
			} else if (arg0 == TransactionResult.CANCEL) {
				TRACE.d("CANCEL");
			} else if (arg0 == TransactionResult.CAPK_FAIL) {
				TRACE.d("CAPK_FAIL");
			} else if (arg0 == TransactionResult.NOT_ICC) {
				TRACE.d("NOT_ICC");
			} else if (arg0 == TransactionResult.SELECT_APP_FAIL) {
				TRACE.d("SELECT_APP_FAIL");
			} else if (arg0 == TransactionResult.DEVICE_ERROR) {
				TRACE.d("DEVICE_ERROR");
			} else if(arg0 == TransactionResult.TRADE_LOG_FULL){
				TRACE.d("pls clear the trace log and then to begin do trade");
//				messageTextView.setText("the trade log has fulled!pls clear the trade log!");
			}else if (arg0 == TransactionResult.CARD_NOT_SUPPORTED) {
				TRACE.d("CARD_NOT_SUPPORTED");
			} else if (arg0 == TransactionResult.MISSING_MANDATORY_DATA) {
				TRACE.d("MISSING_MANDATORY_DATA");
			} else if (arg0 == TransactionResult.CARD_BLOCKED_OR_NO_EMV_APPS) {
				TRACE.d("CARD_BLOCKED_OR_NO_EMV_APPS");
			} else if (arg0 == TransactionResult.INVALID_ICC_DATA) {
				TRACE.d("INVALID_ICC_DATA");
			}else if (arg0 == TransactionResult.FALLBACK) {
				TRACE.d("FALLBACK");
			}else if (arg0 == TransactionResult.NFC_TERMINATED) {
				TRACE.d("NFC_TERMINATED");
			} else if (arg0 == TransactionResult.CARD_REMOVED) {
				TRACE.d("CARD_REMOVED");
			}
		}

		@Override
		public void onRequestUpdateKey(String arg0) {
			
		}

		@Override
		public void onRequestUpdateWorkKeyResult(UpdateInformationResult arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onRequestWaitingUser() {
			TRACE.d("onRequestWaitingUser()");
			callback("please insert/swipe/tap card");
		}

		@Override
		public void onReturnApduResult(boolean arg0, String arg1, int arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnBatchSendAPDUResult(LinkedHashMap<Integer, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnCustomConfigResult(boolean arg0, String arg1) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnDownloadRsaPublicKey(HashMap<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnGetEMVListResult(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnGetPinResult(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnGetQuickEmvResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnNFCApduResult(boolean arg0, String arg1, int arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnPowerOffIccResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnPowerOffNFCResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnPowerOnIccResult(boolean arg0, String arg1, String arg2, int arg3) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnPowerOnNFCResult(boolean arg0, String arg1, String arg2, int arg3) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnReversalData(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnSetMasterKeyResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnSetSleepTimeResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnUpdateEMVRIDResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnUpdateEMVResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturnUpdateIPEKResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onReturniccCashBack(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onSearchMifareCardResult(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onSetBuzzerResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onSetManagementKey(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onSetParamsResult(boolean arg0, Hashtable<String, Object> arg1) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onSetSleepModeTime(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onUpdateMasterKeyResult(boolean arg0, Hashtable<String, String> arg1) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onUpdatePosFirmwareResult(UpdateInformationResult arg0) {
			if(arg0==null){
				return;
			}else if(arg0==UpdateInformationResult.UPDATE_FAIL){
				TRACE.d("update fail");
			}else if(arg0==UpdateInformationResult.UPDATE_SUCCESS){
				TRACE.d("update success");
			}else if(arg0==UpdateInformationResult.UPDATE_PACKET_VEFIRY_ERROR){
				TRACE.d("update packet error");
			}
		}

		@Override
		public void onVerifyMifareCardResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onWaitingforData(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onWriteBusinessCardResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onWriteMifareCardResult(boolean arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void transferMifareData(String arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void verifyMifareULData(Hashtable<String, String> arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void writeMifareULData(String arg0) {
			// TODO Auto-generated method stub
			
		}
    	
    }
}
