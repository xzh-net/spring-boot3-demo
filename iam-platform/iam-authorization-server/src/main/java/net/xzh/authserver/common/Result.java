package net.xzh.authserver.common;

import lombok.Data;

import java.io.Serializable;

@Data
public class Result<T> implements Serializable {

    /**
	 * 
	 */
	private static final long serialVersionUID = 4436252366066300587L;
	private int code;
    private String msg;
    private T data;
    private long timestamp = System.currentTimeMillis();

    public Result() {}

    public Result(int code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    public static <T> Result<T> ok() {
        return new Result<>(200, "success", null);
    }

    public static <T> Result<T> ok(T data) {
        return new Result<>(200, "success", data);
    }

    public static <T> Result<T> ok(String msg, T data) {
        return new Result<>(200, msg, data);
    }

    public static <T> Result<T> fail(String msg) {
        return new Result<>(500, msg, null);
    }

    public static <T> Result<T> fail(int code, String msg) {
        return new Result<>(code, msg, null);
    }
}
