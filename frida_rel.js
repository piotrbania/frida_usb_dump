/**

	this frida script tries to sniff USB traffic on macOS.
	It dumps the data to DUMP_FILE_PATH with some additional ascii markers for further parsing.
	
	OFFSETS_* were dumped on macos bigsur as far as i recall. 
	
	
	- piotr ( piotrbania.com - somewhere in 2021).


**/


// frida -l frida.js --no-pause ./checkra1n --cli
// frida -l frida.js --no-pause ./usb_test
// frida -n checkra1n -l frida.js --no-pause


'use strict'

var connect_ptr;
var classname;
var type;
var total = 0;
var total2 = 0;

// check endianess
// python -c "import sys; print(sys.byteorder)"
// little






var OFFSET_DeviceRequest 		= 0xd0;
var OFFSET_DeviceRequestTO 		= 0xf0;


var OFFSET_QueryInterface 				= 0x8;
var hook_list 				= Array();


// device 

var OFFSET_DeviceRequestAsync 		= 0xd8;
var OFFSET_DeviceRequestAsyncTO		= 0xf8;



// interface 


var OFFSET_ControlRequest 					= 0xc0;
var OFFSET_ControlRequestAsync 				= 0xc8;
var OFFSET_ControlRequestAsyncTO			= 0x130;



var OFFSET_WritePipe 						= 0x100;





var OFFSET_ControlRequestTO 				= 0x128;


var OFFSET_ResetDevice 						= 0xc8;
var OFFSET_USBDeviceReEnumerate				= 0x128;




var array_uuids = Array("kIOUSBDeviceInterfaceID320", "874af642e9d0a201cee08c7c05778b8b",
"kIOUSBDeviceInterfaceID300", "93483d94f7046139ebc2f56cbd69f190",
"kIOUSBDeviceInterfaceID245", "3b475a3b2fd52ffeedb31e0099ad7b97",
"kIOUSBDeviceInterfaceID197", "d7118408d8b809c83e3e3e93030096bb",
"kIOUSBDeviceInterfaceID182", "d511914896c42f15861e80270a00529d",
"kIOUSBDeviceInterfaceID500", "e2485b4b47f03ca33be1eafc07027db5",
"kIOUSBDeviceInterfaceID650", "6a47c2242e1bac4accf2343533914d96",
"kIOUSBDeviceInterfaceID",    "d411f39ed087815c612805270a00458b",
"kIOUSBInterfaceInterfaceID300", "274f4d88dcadeabcf690ab9fd6364083",
"kIOUSBInterfaceInterfaceID245", "4f4b6b0fd2bdba64ad87690436dc3e8e",
"kIOUSBInterfaceInterfaceID220", "d811e82f0ce60d77d0b1dc93030082a5",
"kIOUSBInterfaceInterfaceID197", "d7118408923c3dc63e3e3e9303009296",
"kIOUSBInterfaceInterfaceID182", "d51196484cac2349861e80270a000892",
"kIOUSBInterfaceInterfaceID500", "a74e93b0c3380d6c16acdd5dfb099b80",
"kIOUSBInterfaceInterfaceID550", "7f4845eb3f4de46a9eeaf8993bb98e8e",
"kIOUSBInterfaceInterfaceID650", 	"87408180891a15089f5ddbdffe0a9e8f",
"kIOUSBInterfaceInterfaceID700", 	"1d40a1b09ce5f9177e04c67ae28dc09a",
"kIOUSBInterfaceInterfaceID800", 	"28433b0cb05da8334c7f111ba8fd028f",
"kIOUSBInterfaceInterfaceID", 		"d411f39ee87ac973612805270a00d0b1",
"kIOCFPlugInInterfaceID", 			"d4119c1058e844c26f42c6e45000d491",
"", "");






Process.setExceptionHandler(function(exp) {
  console.warn(JSON.stringify(Object.assign(exp, { _lr: DebugSymbol.fromAddress(exp.context.lr), _pc: DebugSymbol.fromAddress(exp.context.pc) }), null, 2));
  Memory.protect(exp.memory.address, Process.pointerSize, 'rw-');
  return true;
});




function GetUUIDText(raw)
{
	for (var i = 0; array_uuids[i] != ""; i++)
	{
			if (array_uuids[i] == raw) return array_uuids[i-1];
	}

	return "UNKNOWN " + raw;
}


/*

 public var bmRequestType: UInt8
    public var bRequest: UInt8
    public var wValue: UInt16
    public var wIndex: UInt16
    public var wLength: UInt16
    public var pData: UnsafeMutableRawPointer!
    public var wLenDone: UInt32
    
	
*/


function htonl(n)
{
    
    return [
        (n & 0xFF000000) >>> 24,
        (n & 0x00FF0000) >>> 16,
        (n & 0x0000FF00) >>>  8,
        (n & 0x000000FF) >>>  0,
    ];
}


function byteArrayToLong(/*byte[]*/byteArray) {
    var value = 0;
    for ( var i = byteArray.length - 1; i >= 0; i--) {
        value = (value * 256) + parseInt(byteArray[i]);
		console.log("value = " + value + " ( added = " + parseInt(byteArray[i]));
    }

    return value;
};



function swap16(val) {
	
	return val;
	
	//return new UInt64(val).toNumber(); //.toString(16);
	
	//console.log("swap16 val=" + val);
	//return val;
	
    return ((val & 0xFF) << 8)
           | ((val >> 8) & 0xFF);
}


	var gPACKET_COUNTER = 0;
	var gTRACE = 0;

	var DUMP_FILE_PATH 				= "/Users/piotr/Desktop/wireshark_checkrain/frida/dump.txt";
	var DUMP_ENTRY_MARKER_CR		= "III1";
	var DUMP_ENTRY_MARKER_CRTO		= "III2";
	var DUMP_ENTRY_MARKER_CRASYNC	= "III3";
	var DUMP_ENTRY_MARKER_CRASYNCTO	= "III4";
	
	var DUMP_ENTRY_MARKER_WRITEPIPE	= "III5";
	
	
	var DUMP_ENTRY_MARKER_DR		= "DDD1";
	var DUMP_ENTRY_MARKER_DRTO		= "DDD2";	
	var DUMP_ENTRY_MARKER_DRASYNC	= "DDD3";	
	var DUMP_ENTRY_MARKER_DRASYNCTO	= "DDD4";	
		
		
	var DUMP_ENTRY_MARKER_DRESET 	= "RRR1";	// reset device 
	var DUMP_ENTRY_MARKER_ENUM 		= "RRR2";	// USBDeviceReEnumerate is also used for reset device (see darwin_usb.c)
	
	
	
	var DUMP_ENTRY_MARKER_QUERYINTERFACE 		= "QQQQ";
	
	
	
	var DUMP_ENTRY_MARKER_DATA_START	= "DATA";
	var DUMP_ENTRY_MARKER_DATA_END		= "BBBB";
	
	var DUMP_ENTRY_MARKER_RET_END		= "REND";
	
	var IOUSBDevRequest_size 	= 0x18;
	var IOUSBDevRequestTO_size 	= 0x20;
	






	var ENTRY_CONTROLREQUEST	 					= 	0;
	var ENTRY_CONTROLREQUEST_TO	 					= 	1;
	var ENTRY_CONTROLREQUEST_ASYNC 					=	2;
	var ENTRY_WRITEPIPE			 					=	3;
	var ENTRY_CONTROLREQUEST_DEVICEREQUEST			=	5;
	var ENTRY_CONTROLREQUEST_DEVICEREQUEST_TO 		=	6;
	var ENTRY_CONTROLREQUEST_DEVICEREQUEST_ASYNC	=	7;
	var ENTRY_CONTROLREQUEST_DEVICEREQUEST_ASYNC_TO	=	8;
	var ENTRY_CONTROLREQUEST_DEVICE_RESET			=	10;
	var ENTRY_CONTROLREQUEST_DEVICE_ENUMERATE		=	11;
	var ENTRY_CONTROLREQUEST_ASYNC_TO 				=	12;

	var ENTRY_QUERYINTERFACE 						=	13;


	var gDumpFile = 0;
	
	// which_api = 0 (ControlRequest), 1 (ControlRequestTO), 2 (ControlRequestAsync), 3 (WritePipe)
	// DeviceRequest 5
	// DeviceRequestTO 6
	// DeviceRequestAsync 7
	// DeviceRequestAsync 8

	function DumpControlRequestToFile(_this, _pipe, req, ret_code, which_api, data, len)
	{
		
		gTRACE++;
		
		
		var ret_code_num = ret_code.toString(16).padStart(8, "0");	// i don't know how to create bytes from js number, so i use this fucking string version (max 64bits)
		ret_code_num = ret_code_num.substring(0, 8);
		
		
		
		
		if (!gDumpFile) gDumpFile = new File(DUMP_FILE_PATH, "wb")
		
		
		
		if (which_api == ENTRY_QUERYINTERFACE)
		{
			
			console.log("!!! FRIDA: " +gTRACE + " DumpControlRequestToFile: QUERY INTERFACE\r\n");
			
			
			gDumpFile.write(DUMP_ENTRY_MARKER_QUERYINTERFACE);
			gDumpFile.write(ret_code_num); 	gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);
			
			return;
			
			
			
			
		}
		
		if (which_api == ENTRY_WRITEPIPE)
		{
			// WritePipe
			console.log("!!! FRIDA: " +gTRACE + " DumpControlRequestToFile: WritePipe pData=" + data + " len = " + len);
			
			
			gDumpFile.write(DUMP_ENTRY_MARKER_WRITEPIPE);
			
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			
			
			
			gDumpFile.write(Memory.readByteArray(data, len));
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);
			
			
			console.log("RETURN\r\n");
			return;
		}
		
		
		
		
		
		
		
		
		
		if (which_api == ENTRY_CONTROLREQUEST_DEVICE_RESET)
		{
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DRESET);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);
			return;
		}
		
		
		if (which_api == ENTRY_CONTROLREQUEST_DEVICE_ENUMERATE)
		{
			gDumpFile.write(DUMP_ENTRY_MARKER_ENUM);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);
						
			return;
		}
				
		
		

		
		try
		{
			var _bmRequestType	=	req.readU8().toString(16);
			
		} catch(e)
		{
			console.log("!!! FRIDA: " +gTRACE + " DumpControlRequestToFile: unable to read memory: req = " + req);
			return;
		}
		
				
		
		
		
		
		var _bmRequestType		=	req.readU8().toString(16);
		var _bRequest 			=	req.add(1).readU8().toString(16);
		

		var _wValue 			=	req.add(2).readU16().toString(16); 		//uint64( swap16(req.add(2).readU16()) );
		var _wIndex 			=	req.add(4).readU16().toString(16);		//uint64( swap16(req.add(4).readU16()) );  // wValue needs to be converted
				
		
		var _pData 				=   ptr(Memory.readPointer(req.add(8)));
		var _wLength 			=	req.add(6).readU16().toString(16);			//uint64( swap16(req.add(6).readU16()) ); // wlength needs to be converted 
	
	
	
		
		if (ret_code != 0)
		{
			console.log("!!! FRIDA: " +gTRACE + " FAILURE STATUS DumpControlRequestToFile which_api=" + which_api + " req=" + req + " bmRequestType=" + _bmRequestType + " bRequest = " + _bRequest + "  wValue = " + _wValue + "  wIndex=" + _wIndex + " wLength=" + _wLength.toString(16) + " pData=" + _pData + " ret_code=0x" + ret_code +" was a failure skipping\r\n");
			//return;
		}
		
		
		
		
		
		console.log("!!! FRIDA: " +gTRACE + " DumpControlRequestToFile: which_api=" + which_api + "this=" + _this + " pipe=" + _pipe + " req=" + req + " bmRequestType=" + _bmRequestType + " bRequest = " + _bRequest + "  wValue = " + _wValue + "  wIndex=" + _wIndex + " wLength=" + _wLength.toString(16) + " pData=" + _pData);
		
		
		
		// this shit is a must for frida, otherwise in readMemory it will use wrong wLength 
		_wLength = new UInt64("0x"+_wLength);
		
		
		console.log("!!! FRIDA: " +gTRACE + " wLength=" + _wLength + " pData=" + _pData);
		
		
			if ((_wLength == 0x800) || (_wLength == 2048) || (_wLength == "0x800"))
		{
			console.log("!!! FRIDA: " +gTRACE + " INCREASING COUNTER=" + gPACKET_COUNTER);
			
			gPACKET_COUNTER++;
		
			
		}
		
		
		
		
		if (which_api == ENTRY_CONTROLREQUEST) 
		{
			// controlrequest 
			// IOUSBDevRequest(byte bmRequestType, byte bRequest, short wValue, short wIndex, short wLength, Pointer pData, int wLenDone)
			// sizeof(IOUSBDevRequest) = 0x18

			console.log("!!! FRIDA: " +gTRACE + " DumpControlRequestToFile: _pData = " + _pData + " end: " + ptr(_pData).add(_wLength));


			gDumpFile.write(DUMP_ENTRY_MARKER_CR);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			
			// dump binary header
			
			gDumpFile.write(Memory.readByteArray(req, IOUSBDevRequest_size));
			
			// dump pData
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_START);
			if ((_pData != 0) && (_wLength != 0)) gDumpFile.write(Memory.readByteArray(_pData, _wLength));
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);
			
			
		}
		else if (which_api == ENTRY_CONTROLREQUEST_TO) 
		{
			// controlrequest to
			// IOUSBDevRequestTO(byte bmRequestType, byte bRequest, short wValue, short wIndex, short wLength, Pointer pData, int wLenDone, int noDataTimeout, int completionTimeout)
			// sizeof(IOUSBDevRequestTO) = 0x20
			gDumpFile.write(DUMP_ENTRY_MARKER_CRTO);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			
			// dump binary header
			gDumpFile.write(Memory.readByteArray(req, IOUSBDevRequestTO_size));
			
			// dump pData
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_START);
			if ((_pData != 0) && (_wLength != 0))  gDumpFile.write(Memory.readByteArray(_pData, _wLength));
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);			
			
		}
		else if (which_api == ENTRY_CONTROLREQUEST_ASYNC) 
		{
			// ControlRequestAsync
			gDumpFile.write(DUMP_ENTRY_MARKER_CRASYNC);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			
			// dump binary header
			gDumpFile.write(Memory.readByteArray(req, IOUSBDevRequest_size));
			
			// dump pData
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_START);
			if ((_pData != 0) && (_wLength != 0)) gDumpFile.write(Memory.readByteArray(_pData, _wLength));
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);
			
		}		
		else if (which_api == ENTRY_CONTROLREQUEST_ASYNC_TO )
		{
			
			// ControlRequestAsyncTO
			gDumpFile.write(DUMP_ENTRY_MARKER_CRASYNCTO);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			
			// dump binary header
			gDumpFile.write(Memory.readByteArray(req, IOUSBDevRequest_size));
			
			// dump pData
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_START);
			if ((_pData != 0) && (_wLength != 0)) gDumpFile.write(Memory.readByteArray(_pData, _wLength));
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);			
		
		}
		else if (which_api == ENTRY_CONTROLREQUEST_DEVICEREQUEST) 
		{
			// DeviceRequest
			// IOUSBDevRequest(byte bmRequestType, byte bRequest, short wValue, short wIndex, short wLength, Pointer pData, int wLenDone)
			// sizeof(IOUSBDevRequest) = 0x18

			
			console.log("!!! FRIDA: " +gTRACE + " DumpControlRequestToFile: _pData = " + _pData + " end: " + ptr(_pData).add(_wLength));


			gDumpFile.write(DUMP_ENTRY_MARKER_DR);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			
			// dump binary header
			gDumpFile.write(Memory.readByteArray(req, IOUSBDevRequest_size));
			
			// dump pData
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_START);
			if ((_pData != 0) && (_wLength != 0)) gDumpFile.write(Memory.readByteArray(_pData, _wLength));
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);
			
			
		}
		else if (which_api == ENTRY_CONTROLREQUEST_DEVICEREQUEST_TO) 
		{
			// DeviceRequestTO
			// IOUSBDevRequestTO(byte bmRequestType, byte bRequest, short wValue, short wIndex, short wLength, Pointer pData, int wLenDone, int noDataTimeout, int completionTimeout)
			// sizeof(IOUSBDevRequestTO) = 0x20
			gDumpFile.write(DUMP_ENTRY_MARKER_DRTO);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			
			
			
			
			// dump binary header
			gDumpFile.write(Memory.readByteArray(req, IOUSBDevRequestTO_size));
			
			// dump pData
			
			console.log("!!! FRIDA: " +gTRACE + " DUMPING IOUSBDevRequestTO_size=" + IOUSBDevRequestTO_size + " _wLength=" +  _wLength + "_pData = " + _pData + " req = " + req);
			
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_START);
			if ((_pData != 0) && (_wLength != 0))  gDumpFile.write(Memory.readByteArray(_pData, _wLength));
			
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);			
			
		}		
		else if (which_api == ENTRY_CONTROLREQUEST_DEVICEREQUEST_ASYNC) 
		{
			// DeviceRequestAsync
			// IOUSBDevRequest(byte bmRequestType, byte bRequest, short wValue, short wIndex, short wLength, Pointer pData, int wLenDone)
			// sizeof(IOUSBDevRequest) = 0x18

			console.log("!!! FRIDA: " +gTRACE + " DumpControlRequestToFile: _pData = " + _pData + " end: " + ptr(_pData).add(_wLength));


			gDumpFile.write(DUMP_ENTRY_MARKER_DRASYNC);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			
			// dump binary header
			gDumpFile.write(Memory.readByteArray(req, IOUSBDevRequest_size));
			
			// dump pData
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_START);
			if ((_pData != 0) && (_wLength != 0)) gDumpFile.write(Memory.readByteArray(_pData, _wLength));
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);
			
			
		}
		else if (which_api == ENTRY_CONTROLREQUEST_DEVICEREQUEST_ASYNC_TO) 
		{
			// DeviceRequestAsyncTO
			// IOUSBDevRequestTO(byte bmRequestType, byte bRequest, short wValue, short wIndex, short wLength, Pointer pData, int wLenDone, int noDataTimeout, int completionTimeout)
			// sizeof(IOUSBDevRequestTO) = 0x20
			gDumpFile.write(DUMP_ENTRY_MARKER_DRASYNCTO);
			gDumpFile.write(ret_code_num); gDumpFile.write(DUMP_ENTRY_MARKER_RET_END);
			
			// dump binary header
			gDumpFile.write(Memory.readByteArray(req, IOUSBDevRequestTO_size));
			
			// dump pData
			
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_START);
			if ((_pData != 0) && (_wLength != 0))  gDumpFile.write(Memory.readByteArray(_pData, _wLength));
			
			gDumpFile.write(DUMP_ENTRY_MARKER_DATA_END);			
			
		}		
				
		
		
	
		gDumpFile.flush();
	
	}




	 function DumpIORequest(req, Variant2)
	{
		
		
		/*
		
			typedef struct {
				UInt8   	bmRequestType;
				UInt8 	bRequest;
				UInt16 	wValue;
				UInt16 	wIndex;
				UInt16	wLength;
				void * 	pData;		// data pointer
				UInt32	wLenDone;	// # bytes transferred
			} IOUSBDevRequest;	

		*/
		
		
		if (req == 0)
		{
			console.log("!!! FRIDA: " +gTRACE + " DumpIORequest: NO REQUEST TO DUMP, REQ=0\r\n");
			return;
			
		}
		
		
		console.log("!!! FRIDA: " +gTRACE + " DumpIORequest: req=" + req);
		
		
		try {
		
		var _bmRequestType	=	req.readU8().toString(16);
		var _bRequest 		=	req.add(1).readU8().toString(16);
		var _wValue 		=	req.add(2).readU16().toString(16);
		var _wIndex 		=	req.add(4).readU16().toString(16);
		var _wLength		=	req.add(6).readU16().toString(16);	

		} catch(e)
		{
			console.log("!!! FRIDA: " +gTRACE + " DumpIORequest:  unable to read memory: req = " + req);
			return;
		}

		
		console.log("!!! FRIDA: " +gTRACE + " DumpIORequest: req=" + req + " bmRequestType=" + _bmRequestType + " bRequest = " + _bRequest + "  wValue = " + _wValue + "  wIndex=" + _wIndex + " wLength=" + _wLength);
		
		return;
	}



Interceptor.attach(Module.findExportByName("IOKit", "IOCreatePlugInInterfaceForService"), {
    onEnter: function(args) {
		var ret_addr 		= this.returnAddress;
		var plug_ptr 		= args[3];
		
		
		this.plug_ptr_out 	= ptr(plug_ptr); //.toString();
		
        console.log("!!! FRIDA: " +gTRACE + " IOCreatePlugInInterfaceForService called, plug_ptr_out=" + plug_ptr + "  ret_addr = " + ret_addr);
	
    },
    onLeave: function(retval) {
        // If we have a valid connection
		 
		
		console.log("!!! FRIDA: " +gTRACE + " RET IOCreatePlugInInterfaceForService retval == " + retval + " (WE ARE EXPECTING 0)");
        if (retval == 0) {
			
			
			var _p1 					= Memory.readPointer(this.plug_ptr_out);
			_p1 						= Memory.readPointer(_p1);
			
			//console.log("!!! FRIDA: " +gTRACE + " p1 = " +_p1);
			var QueryInterface_addr 	= Memory.readPointer(_p1.add(OFFSET_QueryInterface));
			var QueryInterface_addr2 	= Instruction.parse(QueryInterface_addr); //Memory.readPointer(QueryInterface_addr2);
			
			
			// we need to hook this somehow
			// (*plug)->QueryInterface(plug, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (void *)&dev);
			
			
			console.log("!!! FRIDA: " +gTRACE + " HOOKING QueryInterface = " + QueryInterface_addr + " func addr = " + QueryInterface_addr2);
			
			
			if (QueryInterface_addr in hook_list)
			{
				console.log("FUNCTION ALREAD HOOKED - SKIPPING");
				return retval;
				
			}
			
			
			var old_QueryInterface = new NativeFunction(QueryInterface_addr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
			hook_list[ QueryInterface_addr ] = 1;
			
			
			
			//
			// query interface replacement
			//
			
			Interceptor.replace(QueryInterface_addr, new NativeCallback((_this, _id1, _id2, _dev_out) => {
				
				var ret_addr 		= this.returnAddress;
				
				var ret_bytes 		= ret_addr.readU64().toString(16);
				
				var uuid 			=  _id1.toString(16) + _id2.toString(16);
				var uuid_text 		= GetUUIDText(uuid);
				
				var hook_interface 	= 0;
				
				console.log("!!! FRIDA: " + gTRACE + " in hooked QueryInterface IN dev_out=" + _dev_out + " return=" + ret_addr + " bytes=" + ret_bytes );
				console.log("!!! FRIDA: " + gTRACE + " in hooked QueryInterface IN CFUIID="+uuid_text);
				
				if (uuid_text.includes("InterfaceInterface"))
				{
					console.log("!!! FRIDA: " +gTRACE + " hooking InterfaceInterface");
					hook_interface = 1;
					
					
				}
				
				
				
				
				DumpControlRequestToFile(_this, 0, 0, 0, ENTRY_QUERYINTERFACE, 0, 0);
				
				
				
				
				var res = old_QueryInterface(_this, _id1, _id2, _dev_out);
				var _dev_out_real = Memory.readPointer(_dev_out);
				
				if (_dev_out_real == 0)
				{
					console.log("!!! FRIDA: " +gTRACE + " error _dev_out_real == 0\r\n");
					return res;
				}
				
				
				
				_dev_out_real = Memory.readPointer(_dev_out_real);
				console.log("!!! FRIDA: " +gTRACE + " out hooked QueryInterface OUT res=" + res +" dev_out_real=" + _dev_out_real);
				
				
				//Memory.writePointer(_dev_out, ptr("0x112233445566"));
				//return res;
				
				if (res == 0)
				{
					
					
					
					if (hook_interface == 1)
					{
						
						//return res;
						
						var _addr_ControlRequest 		= Memory.readPointer(_dev_out_real.add(OFFSET_ControlRequest));
						var _addr_ControlRequestTO 		= Memory.readPointer(_dev_out_real.add(OFFSET_ControlRequestTO));
						var _addr_ControlRequestAsync 	= Memory.readPointer(_dev_out_real.add(OFFSET_ControlRequestAsync));
						var _addr_ControlRequestAsyncTO = Memory.readPointer(_dev_out_real.add(OFFSET_ControlRequestAsyncTO));
						
						var _addr_WritePipe 			= Memory.readPointer(_dev_out_real.add(OFFSET_WritePipe));
					
				
						console.log("!!! FRIDA: " +gTRACE + " HOOKING INTERFACE _ControlRequest=" + _addr_ControlRequest + " WritePipe = " + _addr_WritePipe);
					
					
							
						
						//
						// HOOK ControlRequest
						// IOReturn (*ControlRequest)(void *self, UInt8 pipeRef, IOUSBDevRequest *req);
						
						
						
						if (!(_addr_ControlRequest in hook_list))
						{
							console.log("!!! FRIDA: " +gTRACE + " hooking INTERFACE ControlRequest");
							
							hook_list[_addr_ControlRequest] = 1;
							var old_ControlRequest = new NativeFunction(_addr_ControlRequest, 'int', ['pointer', 'pointer', 'pointer']);
							
							Interceptor.replace(_addr_ControlRequest, new NativeCallback((_this, _pipeRef, _req) => {
								var old_req = ptr(_req);
					
					
								console.log("!!! FRIDA: " +gTRACE + " in hooked ControlRequest IN req=" + _req);
					
								//DumpIORequest(ptr(_req), 0);
					
					

								
								
								var res = 0;
								DumpControlRequestToFile(_this, _pipeRef, old_req, res, ENTRY_CONTROLREQUEST, 0, 0);
					
					
								res = old_ControlRequest(_this, _pipeRef, _req);
								
								
								//DumpControlRequestToFile(_this, _pipeRef, old_req, res, ENTRY_CONTROLREQUEST, 0, 0);
								
								return res;
							}, 'int',  ['pointer', 'pointer', 'pointer']));
						}
						
						
						//
						// HOOK ControlRequestTO
						// IOReturn (*ControlRequestTO)(void *self, UInt8 pipeRef, IOUSBDevRequestTO *req);
						
						
						if (!(_addr_ControlRequestTO in hook_list))
						{
							
							console.log("!!! FRIDA: " +gTRACE + " hooking INTERFACE ControlRequestTO");
							
							hook_list[_addr_ControlRequestTO] = 1;
							var old_ControlRequestTO = new NativeFunction(_addr_ControlRequestTO, 'int', ['pointer', 'pointer', 'pointer']);
							
							Interceptor.replace(_addr_ControlRequestTO, new NativeCallback((_this, _pipeRef, _req) => {
								var old_req = ptr(_req);
					
					
								console.log("!!! FRIDA: " +gTRACE + " in hooked ControlRequestTO IN req=" + _req);
					
					
								
								//DumpIORequest(ptr(_req), 1);
								var res = 0;
								DumpControlRequestToFile(_this, _pipeRef, old_req, res, ENTRY_CONTROLREQUEST_TO, 0, 0);
					
					
								res = old_ControlRequestTO(_this, _pipeRef, _req);
								
								
								//DumpControlRequestToFile(_this, _pipeRef, old_req, res, ENTRY_CONTROLREQUEST_TO, 0, 0);
								
								return res;
							}, 'int',  ['pointer', 'pointer', 'pointer']));
						}
												
						
						//
						// ControlRequestAsync
						// IOReturn (*ControlRequestAsync)(void *self, UInt8 pipeRef, IOUSBDevRequest *req, IOAsyncCallback1 callback, void *refCon);
						
						if (!(_addr_ControlRequestAsync in hook_list))
						{
							// DeviceRequest(void *_this, IOUSBDevRequestTO *req)
							
							console.log("!!! FRIDA: " +gTRACE + " hooking INTERFACE ControlRequestAsync");
							
							hook_list[_addr_ControlRequestAsync] = 1;
							var old_ControlRequestAsync = new NativeFunction(_addr_ControlRequestAsync, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
							
							Interceptor.replace(_addr_ControlRequestAsync, new NativeCallback((_this, _pipeRef, _req, _callback, _refCon) => {
								var old_req = ptr(_req);

					
					
								console.log("!!! FRIDA: " +gTRACE + " in hooked ControlRequestAsync IN req=" + _req);
					
								//DumpIORequest(ptr(_req), 0);
								
								
								var res = 0;
								DumpControlRequestToFile(_this, _pipeRef, old_req, res, ENTRY_CONTROLREQUEST_ASYNC, 0, 0);
					
					
								res = old_ControlRequestAsync(_this, _pipeRef, _req, _callback, _refCon);
								
								//DumpControlRequestToFile(_this, _pipeRef, old_req, res, ENTRY_CONTROLREQUEST_ASYNC, 0, 0);
								
								return res;
							}, 'int',  ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']));
						}
						
						//
						// ControlRequestAsyncTO
						// IOReturn (*ControlRequestAsyncTO)(void *self, UInt8 pipeRef, IOUSBDevRequestTO *req, IOAsyncCallback1 callback, void *refCon);
						
						if (!(_addr_ControlRequestAsyncTO in hook_list))
						{
							// DeviceRequest(void *_this, IOUSBDevRequestTO *req)
							
							console.log("!!! FRIDA: " +gTRACE + " hooking INTERFACE ControlRequestAsyncTO");
							
							hook_list[_addr_ControlRequestAsyncTO] = 1;
							var old_ControlRequestAsyncTO = new NativeFunction(_addr_ControlRequestAsyncTO, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
							
							Interceptor.replace(_addr_ControlRequestAsyncTO, new NativeCallback((_this, _pipeRef, _req, _callback, _refCon) => {
								var old_req = ptr(_req);

					
					
								console.log("!!! FRIDA: " +gTRACE + " in hooked ControlRequestAsyncTO IN req=" + _req);
					
								//DumpIORequest(ptr(_req), 0);
								
					
								var res = 0;
								DumpControlRequestToFile(_this, _pipeRef, old_req, res, ENTRY_CONTROLREQUEST_ASYNC_TO, 0, 0);
								
								res = old_ControlRequestAsyncTO(_this, _pipeRef, _req, _callback, _refCon);
								
								//DumpControlRequestToFile(_this, _pipeRef, old_req, res, ENTRY_CONTROLREQUEST_ASYNC_TO, 0, 0);
								
								return res;
							}, 'int',  ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']));
						}
						
						
						
						
												
						
						
						
						
						
						
						
						
						
						
						
						// HOOK WritePipe
						// IOReturn (*WritePipe)(void *self, UInt8 pipeRef, void *buf, UInt32 size);
						
						
						/*
						if (!(_addr_WritePipe in hook_list))
						{
							
							console.log("!!! FRIDA: " +gTRACE + " hooking INTERFACE WritePipe");
							
							hook_list[_addr_WritePipe] = 1;
							var old_WritePipe = new NativeFunction(_addr_WritePipe, 'int', ['pointer', 'pointer', 'pointer', 'int']);
							
							Interceptor.replace(_addr_WritePipe, new NativeCallback((_this, _pipeRef, _buf, _size) => {
					
					
								console.log("!!! FRIDA: " +gTRACE + " in hooked WritePipe IN size=" + _size + " _buf=" + _buf);
					
								
					
								var res = old_WritePipe(_this, _pipeRef, _buf, _size);
								
								
								
								DumpControlRequestToFile(0, res, ENTRY_WRITEPIPE, _buf, _size);
								
								
								return res;
							}, 'int',  ['pointer', 'pointer', 'pointer', 'int']));
						}
						*/												
												
							
							
						return res;
							
							
					}
						
					
					
					
					
					
					//
					//
					//
					// hooking Device Interface APIS 
					//
					//
					
					
					
							
					var _addr_DeviceRequest 		= Memory.readPointer(_dev_out_real.add(OFFSET_DeviceRequest));
					var _addr_DeviceRequestTO 		= Memory.readPointer(_dev_out_real.add(OFFSET_DeviceRequestTO));
					
					var _addr_DeviceRequestAsync 	= Memory.readPointer(_dev_out_real.add(OFFSET_DeviceRequestAsync));
					var _addr_DeviceRequestAsyncTO 	= Memory.readPointer(_dev_out_real.add(OFFSET_DeviceRequestAsyncTO));
					
					
					
					
					var _addr_ResetDevice	 		= Memory.readPointer(_dev_out_real.add(OFFSET_ResetDevice));
					var _addr_USBDeviceReEnumerate 	= Memory.readPointer(_dev_out_real.add(OFFSET_USBDeviceReEnumerate));
					
					
					
					
					// IOReturn (*ControlRequest)(void *self, UInt8 pipeRef, IOUSBDevRequest *req);
					// IOReturn (*ControlRequestAsync)(void *self, UInt8 pipeRef, IOUSBDevRequest *req, IOAsyncCallback1 callback, void *refCon);
					// IOReturn (*WritePipe)(void *self, UInt8 pipeRef, void *buf, UInt32 size);
					
					
					//Memory.writePointer(_dev_out_real.add(OFFSET_DeviceRequestAsync), ptr("0x112233445566"));
					//Memory.writePointer(_dev_out_real.add(OFFSET_DeviceRequestAsyncTO), ptr("0x112233445566"));
					
					
					console.log("!!! FRIDA: " +gTRACE + " HOOKING DeviceRequest=" + _addr_DeviceRequest + "  DeviceRequesTO = " + _addr_DeviceRequestTO);
					
					
					
					
					
					
					//
					// HOOK DeviceRequest
					//
					
					
					
					if (!(_addr_DeviceRequest in hook_list))
					{
						// DeviceRequest(void *_this, IOUSBDevRequestTO *req)
						
						hook_list[_addr_DeviceRequest] = 1;
						var old_DeviceRequest = new NativeFunction(_addr_DeviceRequest, 'int', ['pointer', 'pointer']);
						
						Interceptor.replace(_addr_DeviceRequest, new NativeCallback((_this, _req) => {
							var old_req = ptr(_req);
				
				
							console.log("!!! FRIDA: " +gTRACE + " in hooked DeviceRequest IN req=" + _req);
				
				
							
				
							
							DumpIORequest(ptr(_req), 0);
				
							
							
							var res = 0;
							DumpControlRequestToFile(_this, 0, old_req, res, ENTRY_CONTROLREQUEST_DEVICEREQUEST, 0, 0);
							
				
							res = old_DeviceRequest(_this, _req);
				
				
							//console.log("old_req = " + old_req);
							//DumpControlRequestToFile(_this, 0, old_req, res, ENTRY_CONTROLREQUEST_DEVICEREQUEST, 0, 0);
				
							return res;
							
						}, 'int',  ['pointer', 'pointer']));

					}
					
					
					
					//
					// HOOK DeviceRequestTO
					//
					
					
					
					if (!(_addr_DeviceRequestTO in hook_list))
					{
						// DeviceRequest(void *_this, IOUSBDevRequestTO *req)
						
						hook_list[_addr_DeviceRequestTO] = 1;
						var old_DeviceRequestTO = new NativeFunction(_addr_DeviceRequestTO, 'int', ['pointer', 'pointer']);
						
						Interceptor.replace(_addr_DeviceRequestTO, new NativeCallback((_this, _req) => {
							var old_req = ptr(_req);

				
							console.log("!!! FRIDA: " +gTRACE + " in hooked DeviceRequestTO IN req=" + _req);
				
							var res = 0;
							DumpControlRequestToFile(_this, 0, old_req, res, ENTRY_CONTROLREQUEST_DEVICEREQUEST_TO, 0, 0);
							
							
				
							DumpIORequest(ptr(_req), 1);
							res = old_DeviceRequestTO(_this, _req);
							
							
							//DumpControlRequestToFile(_this, 0, old_req, res, ENTRY_CONTROLREQUEST_DEVICEREQUEST_TO, 0, 0);
				
							return res;
							
						}, 'int',  ['pointer', 'pointer']));

					}					
					
					
					
					
					// DeviceRequestAsync
					// IOReturn (*DeviceRequestAsync)(void *self, IOUSBDevRequest *req, IOAsyncCallback1 callback, void *refCon);
					//

					if (!(_addr_DeviceRequestAsync in hook_list))
					{
						// DeviceRequest(void *_this, IOUSBDevRequestTO *req)
						
						hook_list[_addr_DeviceRequestAsync] = 1;
						var old_DeviceRequestAsync = new NativeFunction(_addr_DeviceRequestAsync, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
						
						Interceptor.replace(_addr_DeviceRequestAsync, new NativeCallback((_this, _req, _callback, _refcon) => {
							var old_req = ptr(_req);

				
							console.log("!!! FRIDA: " +gTRACE + " in hooked DeviceRequestAsync IN req=" + _req);
				
				
							DumpIORequest(ptr(_req), 1);
							
							
							var res = 0;
							DumpControlRequestToFile(_this, 0, old_req, res, ENTRY_CONTROLREQUEST_DEVICEREQUEST_ASYNC, 0, 0);
							
							
							var res = old_DeviceRequestAsync(_this, _req, _callback, _refcon);
							//DumpControlRequestToFile(_this, 0, old_req, res, ENTRY_CONTROLREQUEST_DEVICEREQUEST_ASYNC, 0, 0);
				
							return res;
							
						}, 'int',  ['pointer', 'pointer', 'pointer', 'pointer']));

					}					
															
					
					
					
					//
					// DeviceRequestAsyncTO
					// tego uzywa libusb
					// darwin_usb.c
					//
					// IOReturn (*DeviceRequestAsyncTO)(void *self, IOUSBDevRequestTO *req, IOAsyncCallback1 callback, void *refCon);
					if (!(_addr_DeviceRequestAsyncTO in hook_list))
					{
						// DeviceRequest(void *_this, IOUSBDevRequestTO *req)
						
						hook_list[_addr_DeviceRequestAsyncTO] = 1;
						var old_DeviceRequestAsyncTO = new NativeFunction(_addr_DeviceRequestAsyncTO, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
						
						Interceptor.replace(_addr_DeviceRequestAsyncTO, new NativeCallback((_this, _req, _callback, _refcon) => {
							var old_req = ptr(_req);

				
							console.log("!!! FRIDA: " +gTRACE + " in hooked DeviceRequestAsyncTO IN req=" + _req);
				
				
							DumpIORequest(ptr(_req), 1);
							
							var res = 0;
							DumpControlRequestToFile(_this, 0, old_req, res, ENTRY_CONTROLREQUEST_DEVICEREQUEST_ASYNC_TO, 0, 0);
							
							res = old_DeviceRequestAsyncTO(_this, _req, _callback, _refcon);
							//DumpControlRequestToFile(_this, 0, old_req, res, ENTRY_CONTROLREQUEST_DEVICEREQUEST_ASYNC_TO, 0, 0);
				
							return res;
							
						}, 'int',  ['pointer', 'pointer', 'pointer', 'pointer']));

					}



					//
					//
					// IOReturn (*USBDeviceReEnumerate)(void *self, UInt32 options);
					//
					//
					if (!(_addr_ResetDevice in hook_list))
					{
						// IOReturn (*ResetDevice)(void *self);
						hook_list[_addr_ResetDevice] = 1;
						var old_ResetDevice = new NativeFunction(_addr_ResetDevice, 'int', ['pointer']);
						Interceptor.replace(_addr_ResetDevice, new NativeCallback((_this) => {
							console.log("!!! FRIDA: " +gTRACE + " in hooked ResetDevice IN ");
							var res = old_ResetDevice(_this);
							DumpControlRequestToFile(_this, 0, 0, res, ENTRY_CONTROLREQUEST_DEVICE_RESET, 0, 0);
				
							return res;
						}, 'int',  ['pointer']));

					}
					
					
					
					//
					//
					// RESET DEVICE
					//
					//
					
					if (!(_addr_USBDeviceReEnumerate in hook_list))
					{
						// IOReturn (*USBDeviceReEnumerate)(void *self, UInt32 options);
						hook_list[_addr_USBDeviceReEnumerate] = 1;
						var old_USBDeviceReEnumerate = new NativeFunction(_addr_USBDeviceReEnumerate, 'int', ['pointer', 'pointer']);
						Interceptor.replace(_addr_USBDeviceReEnumerate, new NativeCallback((_this, _options) => {
							console.log("!!! FRIDA: " +gTRACE + " in hooked USBDeviceReEnumerate IN ");
							var res = old_USBDeviceReEnumerate(_this, _options);
							DumpControlRequestToFile(_this, 0, 0, res, ENTRY_CONTROLREQUEST_DEVICE_ENUMERATE, 0, 0);
				
							return res;
						}, 'int',  ['pointer', 'pointer']));

					}										
					
					
					
				}

				return res;
			}, 'int',  ['pointer', 'pointer', 'pointer', 'pointer']));


			
			
			
			
			
			console.log("!!! FRIDA: " +gTRACE + " RET IOCreatePlugInInterfaceForService to be hooked QueryInterface=" + QueryInterface_addr);
        }
		
		//retval.replace(1); return retval;
    },
	
	

	
});




Interceptor.attach(Module.findExportByName("IOKit", "IOServiceOpen"), {
    onEnter: function(args) {
        // console.log("!!! FRIDA: " +gTRACE + " IOServiceOpen called");
        connect_ptr = args[3]; // io_connect_t *connect
        classname = Memory.alloc(256);
        // Determine the class name of the IOKit object
        var IOObjectGetClass = Module.findExportByName(null, "IOObjectGetClass");
        var IOObjectGetClassFunc = new NativeFunction(ptr(IOObjectGetClass), 'int', ['pointer', 'pointer']);
        IOObjectGetClassFunc(args[0], classname);
        type = args[2];
		
		var class_str = Memory.readUtf8String(classname);
        console.log("!!! FRIDA: " +gTRACE + " IOServiceOpen(" + args[0] + ", " + args[1] + ", " + args[2] + ", " + args[3] + "); CLASS="+class_str);
    },
    onLeave: function(retval) {
        // If we have a valid connection
        if (retval == 0) {
            var handle = Memory.readU32(connect_ptr);
            var userclient = Memory.readUtf8String(classname);

            //service_ids[handle] = [userclient,type];
        }
    }
});



async function onChildAdded(child) {
  try {
    console.log('[*] onChildAdded:', child);

  } catch (e) {
    console.error(e);
  }
}



/*

Interceptor.attach(Module.findExportByName(null, 'printf'), {
  onEnter(args) {
    
	
    const path = Memory.readUtf8String(args[0])
    console.log('printf: ', path);

  }
})
*/


Interceptor.attach(Module.findExportByName(null, 'posix_spawn'), {
  onEnter(args) {
    this.ppid = args[0]
    const attr = args[3];

  },
  onLeave() {
    const pid = Memory.readInt(this.ppid)
    console.log('posix_spawn pid:', pid)
    //send({ event: 'spawn', pid })
  }
})

Interceptor.attach(Module.findExportByName(null, 'fork'), {
  onEnter(args) {
    this.ppid = args[0]
    const attr = args[3];
  },
  onLeave: function(retval) {
	console.log("!!! FRIDA: " +gTRACE + " FORK() returned " + retval)
  }
})