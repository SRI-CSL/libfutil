all:
	@echo "No separate compilation for now"

clean:
	@echo "* Cleansing"
	@rm -f *.o *.so *.lo *.la *.slo *.loT *.d
	@rm -f src/*.o src/*.so src/*.lo src/*.la src/*.slo src/*.loT src/*.d
	@rm -f src/db/*.o src/db/*.so src/db/*.lo src/db/*.la src/db/*.slo src/db/*.loT src/db/*.d
	@rm -f src/.libs/*.o src/.libs/*.so src/.libs/*.lo src/.libs/*.la src/.libs/*.slo src/.libs/*.loT src/.libs/*.d
	@rm -f src/rfc6234/*.o src/rfc6234/*.so src/rfc6234/*.lo src/rfc6234/*.la src/rfc6234/*.slo src/rfc6234/*.loT src/rfc6234/*.d

