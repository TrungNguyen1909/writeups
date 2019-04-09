---
title: "matesCTF babyOVERFLOW"
date: 2018-10-10T11:35:23+07:00
Tags: ["matesCTF", "CTF", "pwn","stack-buffer-overflow"]
Language: ["Vietnamese"]
---

# babyOVERFLOW
<meta charset="UTF-8">

Tên file bài này gợi ý rất nhiều.

"baby" thường được dùng trong CTF chỉ những bài đơn giản dành cho người mới

"OVERFLOW" ở đây thì chỉ đến stack buffer overflow.

Chạy nó, nhập vào thì nó in ra lại đúng như thế.

Ta có thể thử nhập vào "%x" để xem có format string không thì kết quả là chương trình chạy bình thường

Thử với 1 input thật dài thì thấy không có lỗi gì xảy ra.

`Ctrl+D` để gửi `EOF` thì cũng không thoát chương trình. Mình thử viết `\x00` bằng printf thì chương trình dừng.
Bằng Code Python inline, mình thử in ra 100 cái `\x00` thì thấy

```
*** stack smashing detected ***: <unknown> terminated
Aborted
```

À tức là đây chính xác là 1 bài BOF cơ bản có stack canary

Giờ là lúc để checksec binary:

```

	Arch:     amd64-64-little
	
	RELRO:    Partial RELRO
	
	Stack:    Canary found
	
	NX:       NX enabled
	
	PIE:      No PIE (0x400000)
```

Chúng ta có 1 binary 64bit, no-PIE, NX(W^X) có canary. 

## Leak stack canary
Mình dùng pattern & gdb break tại đoạn kiểm tra cookies thì tìm ra được cookies ở offset 71(cách chữ cái đầu tiên là 71 kí tự)

*Stack cookies luôn được ghi bắt đầu bằng null bytes `\x00` (little-endian) để tránh puts hoặc printf in ra.*

OK, vì ta biết nó luôn luôn như vậy nên ta ghi đè lên nó để puts có thể leak được canary ra.

Vì vậy sau đó, puts sẽ in ra giá trị canary ở cuối.

Như vậy là ta có thể leak được canary 1 cách dễ dàng.

Payload: 
72 junk bytes.

## Exploit
Stack:

```

Stack Cookies------------|
					  
-------------------------|

Saved RBP----------------|

-------------------------|

Function return address--|

-------------------------|

```

Trong khi reverse thì có thể nhận thấy rằng vòng lặp đọc-viết sẽ kết thúc khi kí tự đầu của input = `\x00`
Ta có sẵn hàm `canyourunme` để chạy shell
Payload:

71 Bytes + Canary + 8 bytes + vị trí của `canyourunme` + 4

Không hiểu tại sao mà nếu không + 4 thì sẽ ăn segfault ở server. Mình tốn cả tiếng đồng hồ để có thể qua được đoạn này

Có lẽ là do `push rbp;mov rbp,rsp` có gì đó không đúng.

Anyway là sau đó `cat flag` là ta sẽ có flag

</meta>
