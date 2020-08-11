#ifndef _LIST_H
#define _LIST_H

#include <windows.h>

typedef struct LINKED_LIST
{
	struct LINKED_LIST* NextList;
	BOOL Flag;

	LPVOID Content;
	DWORD ContentSize;
}LINKED_LIST, * PLINKED_LIST;

PLINKED_LIST CreateLinkedList()
{
	PLINKED_LIST ret = (PLINKED_LIST)LocalAlloc(LPTR, sizeof(LINKED_LIST));
	ret->Flag = 1;

	return ret;
}

int AddLinkedList(PLINKED_LIST list, LPVOID Content, DWORD Size)
{
	for (;;)
	{
		if (list->NextList == NULL) break;
		list = list->NextList;
	}

	list->NextList = (PLINKED_LIST)LocalAlloc(LPTR, sizeof(LINKED_LIST));
	if (list->NextList == NULL) return FALSE;

	list->Content = LocalAlloc(LPTR, Size);

	if (list->Content == NULL) return FALSE;
	memcpy(list->Content, Content, Size);

	list->NextList->NextList = NULL;
	list->ContentSize = Size;
	list->Flag = FALSE;

	return TRUE;
}


int FindLinkedList(PLINKED_LIST list, LPVOID Content, DWORD Size)
{
	for (; list->NextList != NULL; list = list->NextList)
	{
		if (memcmp(list->Content, Content, Size) == 0) return FALSE;
	}

	return TRUE;
}


void FreeLinkedList(PLINKED_LIST list)
{
	PLINKED_LIST temp = list;
	int i = 0;
	for (;; i++)
	{
		PLINKED_LIST p = temp->NextList;

		LocalFree(temp->Content);
		LocalFree(temp);

		if (p == NULL) break;

		temp = p;
	}
}

BOOL DeleteLinkedList(PLINKED_LIST* list, int pos)
{
	if (pos != 0)
	{
		PLINKED_LIST temp = *list;
		int i = 0;
		for (; temp->NextList != NULL; temp = temp->NextList)
		{
			if (i + 1 == pos)
			{
				PLINKED_LIST p = temp->NextList;

				if (p != NULL)
				{
					LINKED_LIST t = *p;

					temp->NextList = t.NextList;

					LocalFree(t.Content);
					LocalFree(p);

					t.Content = 0;
					p = 0;
				}

				break;
			}

			i++;
		}
	}
	else
	{
		LINKED_LIST temp = **list;

		LocalFree(temp.Content);
		LocalFree(list);

		*list = temp.NextList;
	}

	return TRUE;
}


#endif