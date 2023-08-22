package cn.zifangsky.license;

import java.io.Serializable;
import java.util.List;

/**
 * 自定义需要校验的License参数
 *
 * @author zifangsky
 * @date 2018/4/23
 * @since 1.0.0
 */
public class LicenseCheckModel implements Serializable{

    private static final long serialVersionUID = 8600137500316662317L;
    /**
     * 可被允许的IP地址
     */
    private List<String> ipAddress;

    /**
     * 可被允许的MAC地址
     */
    private List<String> macAddress;

    /**
     * 可被允许的CPU序列号
     */
    private String cpuSerial;

    public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	/**
     * 可被允许的主板序列号
     */
    private String mainBoardSerial;
    
    public String getStartTime() {
		return startTime;
	}

	public void setStartTime(String startTime) {
		this.startTime = startTime;
	}

	public String getEndTime() {
		return endTime;
	}

	public void setEndTime(String endTime) {
		this.endTime = endTime;
	}

	//证书唯一码
    private String code;
    
    //证书授权时常
    private String day;
    
    
    private String startTime;
    
    private String endTime;
    
    

    public String getDay() {
		return day;
	}

	public void setDay(String day) {
		this.day = day;
	}

	public List<String> getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(List<String> ipAddress) {
        this.ipAddress = ipAddress;
    }

    public List<String> getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(List<String> macAddress) {
        this.macAddress = macAddress;
    }

    public String getCpuSerial() {
        return cpuSerial;
    }

    public void setCpuSerial(String cpuSerial) {
        this.cpuSerial = cpuSerial;
    }

    public String getMainBoardSerial() {
        return mainBoardSerial;
    }

    public void setMainBoardSerial(String mainBoardSerial) {
        this.mainBoardSerial = mainBoardSerial;
    }

    @Override
    public String toString() {
        return "LicenseCheckModel{" +
                "ipAddress=" + ipAddress +
                ", macAddress=" + macAddress +
                ", cpuSerial='" + cpuSerial + '\'' +
                ", mainBoardSerial='" + mainBoardSerial + '\'' +
                '}';
    }
}
