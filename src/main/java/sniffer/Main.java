package sniffer;

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class Main {
	public static String INTERFACE = "192.168.2.129";
	
    public static void main(String[] args)
    {
        // The class that will store the network device
        // we want to use for capturing.
        PcapNetworkInterface device = null;       
        InetAddress addr = null;

        try {        	
            addr = InetAddress.getByName(INTERFACE);
            device = Pcaps.getDevByAddress(addr);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PcapNativeException e) {
			e.printStackTrace();
		}
        
        // Open the device and get a handle
        int snapshotLength = 65536; // in bytes   
        int readTimeout = 50; // in milliseconds                   
        final PcapHandle handle;
        try {
			handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
			PcapDumper dumper = handle.dumpOpen("dump.pcap");
			
	        // Create a listener that defines what to do with the received packets
	        PacketListener listener = new PacketListener() {
	            @Override
	            public void gotPacket(Packet packet) {
	                // Override the default gotPacket() function and process packet
	                System.out.println(handle.getTimestamp());
	                System.out.println(packet);
	                try {
						dumper.dump(packet, handle.getTimestamp());
					} catch (NotOpenException e) {
						e.printStackTrace();
					}
	            }
	        };
	        
            int maxPackets = Integer.MAX_VALUE;
            //handle.loop(maxPackets, listener);
            handle.loop(maxPackets, dumper);
            
            // Cleanup when complete
            handle.close();
            dumper.close();
		} catch (PcapNativeException | InterruptedException | NotOpenException e1) {
			e1.printStackTrace();
		}
    }
}
