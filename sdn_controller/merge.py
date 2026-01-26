# ... Bên trong vòng lặp for stat in ev.msg.body ...

                if key in self.flow_history:
                    (old_packet_count, old_byte_count, old_ts) = self.flow_history[key]
                    period = monitor_ts - old_ts
                    
                    if period > 0:
                        delta_packet = packet_count - old_packet_count
                        # Lọc nhiễu: Nếu delta âm (do switch reset) thì coi như 0
                        if delta_packet < 0: delta_packet = 0
                        
                        pps = delta_packet / period
                    else:
                        pps = 0
                else:
                    # [FIX QUAN TRỌNG] 
                    # Nếu lần đầu nhìn thấy Flow (hoặc Flow vừa bị xóa khỏi cache),
                    # KHÔNG ĐƯỢC lấy tổng số chia cho thời gian.
                    # Phải coi vận tốc tức thời là 0 để chờ mẫu tiếp theo.
                    pps = 0
                    
                # Cập nhật lại lịch sử cho lần đo sau
                self.flow_history[key] = (packet_count, byte_count, monitor_ts)

                # ... (Phần logic kiểm tra ngưỡng giữ nguyên) ...