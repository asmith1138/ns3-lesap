build_lib_example(
  NAME lesap-aodv
  SOURCE_FILES lesap-aodv.cc
  LIBRARIES_TO_LINK
    ${libwifi}
    ${libinternet}
    ${liblesap-aodv}
    ${libinternet-apps}
)
