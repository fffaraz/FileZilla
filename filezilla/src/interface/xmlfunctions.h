/*
 * xmlfunctions.h declares some useful xml helper functions, especially to
 * improve usability together with wxWidgets.
 */

#ifndef FILEZILLA_INTERFACE_XMLFUNCTIONS_HEADER
#define FILEZILLA_INTERFACE_XMLFUNCTIONS_HEADER

#include "../commonui/xml_file.h"

bool SaveWithErrorDialog(CXmlFile& file, bool updateMetadata = true);

// Function to save CServer objects to the XML file
void SetServer(pugi::xml_node node, Site const& site);

#endif
